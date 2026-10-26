#!/usr/bin/env bash
# connector-pki.sh — генерация PKI для grantor connector (ADR-0002/ADR-0006,
# docs/connector-deployment.md).
#
# Создаёт:
#   * выделенный connector CA (EC P-256, ~5 лет);
#   * серверный сертификат gateway c SAN из аргументов (mTLS server);
#   * клиентские сертификаты connector'ов (CN = connector id, mTLS client);
#   * Ed25519-ключи подписи заданий: приватный PKCS#8 PEM для gateway
#     (GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY) и публичный PKIX PEM для
#     connector (GRANTOR_CONNECTOR_VERIFY_KEY) — ровно те кодировки,
#     которые читают internal/connector/gateway/env.go и cmd/connector.
#
# Все артефакты — PEM-файлы на диске: бинарники берут ПУТИ к файлам из
# GRANTOR_CONNECTOR_* переменных, значения ключей в env не передаются.
#
# Свойства:
#   * только openssl + POSIX-утилиты; работает на macOS bash 3.2 и linux;
#   * существующие файлы не перезаписываются без --force; уже полностью
#     сгенерированный компонент пропускается (можно до-генерировать
#     нового connector'а к существующему CA);
#   * секреты в stdout не печатаются: только пути к файлам и текст
#     команд `vault kv`, которые оператор выполняет сам.
#
# Использование:
#   scripts/connector-pki.sh \
#     --out-dir ./pki \
#     --gateway-san dns:grantor-connector-gateway.example.com,ip:10.20.0.15 \
#     --connector-id segment-a \
#     [--connector-id segment-b ...] \
#     [--ca-days 1825] [--cert-days 825] [--force]
#
# Требуется openssl с поддержкой Ed25519 (`genpkey -algorithm ed25519`).
# Системный LibreSSL старых macOS может её не иметь — тогда укажите
# другой бинарь: OPENSSL_BIN=/opt/homebrew/opt/openssl/bin/openssl.

set -euo pipefail

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

OUT_DIR=""
GATEWAY_SAN=""
CONNECTOR_IDS=""
CA_DAYS=1825
CERT_DAYS=825
FORCE=0

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

err() {
  echo "connector-pki: $*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ "$#" -ge 2 ] || err "--out-dir требует значение"
      OUT_DIR="$2"; shift 2 ;;
    --gateway-san)
      [ "$#" -ge 2 ] || err "--gateway-san требует значение"
      GATEWAY_SAN="$2"; shift 2 ;;
    --connector-id)
      [ "$#" -ge 2 ] || err "--connector-id требует значение"
      case "$2" in
        (*[!A-Za-z0-9._-]*) err "connector id '$2': допустимы только [A-Za-z0-9._-]" ;;
      esac
      CONNECTOR_IDS="${CONNECTOR_IDS} $2"; shift 2 ;;
    --ca-days)
      [ "$#" -ge 2 ] || err "--ca-days требует значение"
      CA_DAYS="$2"; shift 2 ;;
    --cert-days)
      [ "$#" -ge 2 ] || err "--cert-days требует значение"
      CERT_DAYS="$2"; shift 2 ;;
    --force)
      FORCE=1; shift ;;
    -h|--help)
      usage 0 ;;
    *)
      err "неизвестный аргумент: $1 (см. --help)" ;;
  esac
done

[ -n "${OUT_DIR}" ] || err "--out-dir обязателен"
[ -n "${GATEWAY_SAN}" ] || err "--gateway-san обязателен (dns:host[,ip:a.b.c.d,...])"
[ -n "${CONNECTOR_IDS}" ] || err "нужен хотя бы один --connector-id"

command -v "${OPENSSL_BIN}" >/dev/null 2>&1 || err "openssl не найден: ${OPENSSL_BIN}"

# Ed25519 обязателен для ключей подписи заданий; проверяем заранее, чтобы
# не падать посреди генерации (системный LibreSSL может не уметь).
if ! "${OPENSSL_BIN}" genpkey -algorithm ed25519 2>/dev/null | grep -q "PRIVATE KEY"; then
  err "этот openssl не поддерживает 'genpkey -algorithm ed25519'; задайте OPENSSL_BIN (например, openssl из brew)"
fi

# subjectAltName для конфига openssl: dns:x -> DNS:x, ip:y -> IP:y.
SAN_LIST=""
OLD_IFS="$IFS"
IFS=','
for entry in ${GATEWAY_SAN}; do
  IFS="$OLD_IFS"
  case "${entry}" in
    dns:*) san="DNS:${entry#dns:}" ;;
    ip:*)  san="IP:${entry#ip:}" ;;
    *)     err "--gateway-san: запись '${entry}' должна начинаться с dns: или ip:" ;;
  esac
  if [ -z "${SAN_LIST}" ]; then
    SAN_LIST="${san}"
  else
    SAN_LIST="${SAN_LIST},${san}"
  fi
  IFS=','
done
IFS="$OLD_IFS"

# Первый DNS SAN — CN серверного сертификата (косметика: доверие идёт по SAN).
GATEWAY_CN="${SAN_LIST%%,*}"
GATEWAY_CN="${GATEWAY_CN#DNS:}"
GATEWAY_CN="${GATEWAY_CN#IP:}"

umask 077

CA_DIR="${OUT_DIR}/ca"
GW_DIR="${OUT_DIR}/gateway"
SIGN_DIR="${OUT_DIR}/signing"
mkdir -p "${CA_DIR}" "${GW_DIR}" "${SIGN_DIR}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/connector-pki.XXXXXX")"
cleanup() {
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

# component_state <файлы...>: "complete" — все существуют, "absent" — ни
# одного, "partial" — часть. Управляет skip/refuse без --force.
component_state() {
  local total=0 present=0 f
  for f in "$@"; do
    total=$((total + 1))
    [ -e "${f}" ] && present=$((present + 1))
  done
  if [ "${present}" -eq 0 ]; then
    echo absent
  elif [ "${present}" -eq "${total}" ]; then
    echo complete
  else
    echo partial
  fi
}

# guard <имя-компонента> <файлы...>: 0 — генерировать, 1 — пропустить.
guard() {
  local name="$1" state
  shift
  state="$(component_state "$@")"
  if [ "${FORCE}" -eq 1 ]; then
    return 0
  fi
  case "${state}" in
    absent)
      return 0 ;;
    complete)
      echo "connector-pki: ${name}: уже существует, пропускаю (--force для перегенерации)"
      return 1 ;;
    partial)
      err "${name}: часть файлов уже существует ($*): уберите остатки или используйте --force" ;;
  esac
}

# --- 1. Connector CA (EC P-256) ------------------------------------------

CA_KEY="${CA_DIR}/ca.key"
CA_CRT="${CA_DIR}/ca.crt"

cat > "${WORK_DIR}/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = grantor-connector-ca

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

if guard "CA" "${CA_KEY}" "${CA_CRT}"; then
  "${OPENSSL_BIN}" genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
    -out "${CA_KEY}" 2>/dev/null
  "${OPENSSL_BIN}" req -x509 -new -key "${CA_KEY}" \
    -config "${WORK_DIR}/ca.cnf" \
    -days "${CA_DAYS}" -sha256 -out "${CA_CRT}"
  chmod 644 "${CA_CRT}"
fi

[ -e "${CA_KEY}" ] && [ -e "${CA_CRT}" ] || err "CA не сгенерирован (${CA_KEY}, ${CA_CRT})"

# issue_cert <key> <csr-cnf> <ext-cnf> <crt>: EC P-256 ключ + CSR + подпись CA.
issue_cert() {
  local key="$1" csr_cnf="$2" ext_cnf="$3" crt="$4"
  "${OPENSSL_BIN}" genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
    -out "${key}" 2>/dev/null
  "${OPENSSL_BIN}" req -new -key "${key}" -config "${csr_cnf}" \
    -out "${WORK_DIR}/req.csr"
  "${OPENSSL_BIN}" x509 -req -in "${WORK_DIR}/req.csr" \
    -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -days "${CERT_DAYS}" -sha256 \
    -extfile "${ext_cnf}" -extensions v3_ext \
    -out "${crt}" 2>/dev/null
  chmod 644 "${crt}"
  rm -f "${WORK_DIR}/req.csr"
}

# --- 2. Серверный сертификат gateway -------------------------------------

GW_KEY="${GW_DIR}/server.key"
GW_CRT="${GW_DIR}/server.crt"

cat > "${WORK_DIR}/gw-csr.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = ${GATEWAY_CN}
EOF

cat > "${WORK_DIR}/gw-ext.cnf" <<EOF
[v3_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = ${SAN_LIST}
EOF

if guard "gateway server cert" "${GW_KEY}" "${GW_CRT}"; then
  issue_cert "${GW_KEY}" "${WORK_DIR}/gw-csr.cnf" "${WORK_DIR}/gw-ext.cnf" "${GW_CRT}"
fi

# --- 3. Клиентские сертификаты connector'ов ------------------------------

for connector_id in ${CONNECTOR_IDS}; do
  conn_dir="${OUT_DIR}/connectors/${connector_id}"
  mkdir -p "${conn_dir}"
  conn_key="${conn_dir}/client.key"
  conn_crt="${conn_dir}/client.crt"

  cat > "${WORK_DIR}/conn-csr.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = ${connector_id}
EOF

  cat > "${WORK_DIR}/conn-ext.cnf" <<'EOF'
[v3_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

  if guard "connector '${connector_id}' client cert" "${conn_key}" "${conn_crt}"; then
    issue_cert "${conn_key}" "${WORK_DIR}/conn-csr.cnf" "${WORK_DIR}/conn-ext.cnf" "${conn_crt}"
  fi
done

# --- 4. Ed25519 ключи подписи заданий ------------------------------------

SIGN_KEY="${SIGN_DIR}/sign.key"
VERIFY_PUB="${SIGN_DIR}/verify.pub"

if guard "job signing keypair" "${SIGN_KEY}" "${VERIFY_PUB}"; then
  # PKCS#8 PEM — формат, который парсит gateway (env.go:
  # parseEd25519PrivateKey); публичный PKIX PEM читает cmd/connector
  # (parseEd25519PublicKey).
  "${OPENSSL_BIN}" genpkey -algorithm ed25519 -out "${SIGN_KEY}" 2>/dev/null
  "${OPENSSL_BIN}" pkey -in "${SIGN_KEY}" -pubout -out "${VERIFY_PUB}"
  chmod 644 "${VERIFY_PUB}"
fi

# --- 5. Сводка (без секретов) --------------------------------------------

cat <<EOF

connector-pki: готово. Файлы (приватные ключи — mode 600):

  CA:            ${CA_CRT}
                 ${CA_KEY}
  gateway:       ${GW_CRT}  (SAN: ${SAN_LIST})
                 ${GW_KEY}
  signing:       ${SIGN_KEY}  (Ed25519 PKCS#8, приватный — только gateway)
                 ${VERIFY_PUB}  (Ed25519 PKIX, публичный — connector'ам)
EOF
for connector_id in ${CONNECTOR_IDS}; do
  cat <<EOF
  connector:     ${OUT_DIR}/connectors/${connector_id}/client.crt  (CN=${connector_id})
                 ${OUT_DIR}/connectors/${connector_id}/client.key
EOF
done

cat <<EOF

Дальше — положить материал в центральный Vault организации (значения
берутся из файлов через @, в историю shell секреты не попадают; пути
<mount>/<env> подставьте свои, см. docs/connector-deployment.md):

  # Сторона gateway (чарт grantor, ExternalSecret grantor-app):
  vault kv patch <mount>/<env>/grantor/app \\
    connector_gateway_tls_cert=@${GW_CRT} \\
    connector_gateway_tls_key=@${GW_KEY} \\
    connector_gateway_client_ca=@${CA_CRT} \\
    connector_gateway_sign_key=@${SIGN_KEY}

  # Фиксированный id read-only токена dev-Vault (переходно, пока стек не
  # переехал на общий Vault; генерируется отдельно, НЕ файл PKI):
  vault kv patch <mount>/<env>/grantor/app \\
    vault_connector_token=\$(openssl rand -hex 32)

EOF
for connector_id in ${CONNECTOR_IDS}; do
  cat <<EOF
  # Сторона connector '${connector_id}' (чарт grantor-connector в сегменте):
  vault kv put <mount>/<env>/grantor/connector-${connector_id} \\
    connector_tls_cert=@${OUT_DIR}/connectors/${connector_id}/client.crt \\
    connector_tls_key=@${OUT_DIR}/connectors/${connector_id}/client.key \\
    connector_ca=@${CA_CRT} \\
    connector_verify_key=@${VERIFY_PUB} \\
    vault_token=<токен Vault сегмента с read-доступом к credentials целей>

EOF
done

echo "connector-pki: после записи в Vault удалите локальные копии приватных ключей."
