#!/usr/bin/env bash
# connector-cert-rotate.sh — ротация листовых сертификатов connector.
#
# Ротация листовых при неизменном CA безопасна и не требует окна: обе
# стороны продолжают доверять и старым, и новым сертификатам, поэтому
# порядок перезапуска не важен.
#
# Скрипт делает всё, что раньше приходилось руками: забирает CA из Vault,
# выпускает новые сертификаты gateway и connector'ов, кладёт их обратно в
# Vault и удаляет локальные копии. Перезапуск подов остаётся на reloader —
# он видит смену секрета и делает это сам (values reloader.enabled).
#
# Вне Kubernetes перезапуск сервиса остаётся ручным: скрипт умеет
# выгрузить PEM в каталог (--export-dir) для переноса на VM.
#
# Использование:
#   scripts/connector-cert-rotate.sh \
#     --gateway-san dns:gw-grantor.example.com \
#     --connector-id test \
#     [--ca-path security/grantor-connector-ca] \
#     [--gateway-path devops/services/grantor] \
#     [--connector-path-prefix devops/services/grantor-connector-] \
#     [--cert-days 1825] [--export-dir ./out]
#
# Переменные окружения: VAULT_ADDR, VAULT_TOKEN, VAULT_KV_MOUNT (по
# умолчанию infra).

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-infra}"
CA_PATH="security/grantor-connector-ca"
GATEWAY_PATH="devops/services/grantor"
CONNECTOR_PREFIX="devops/services/grantor-connector-"
CERT_DAYS=1825
EXPORT_DIR=""
GATEWAY_SAN=""
CONNECTOR_IDS=()

err() { echo "connector-cert-rotate: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --gateway-san) GATEWAY_SAN="$2"; shift 2 ;;
    --connector-id) CONNECTOR_IDS+=("$2"); shift 2 ;;
    --ca-path) CA_PATH="$2"; shift 2 ;;
    --gateway-path) GATEWAY_PATH="$2"; shift 2 ;;
    --connector-path-prefix) CONNECTOR_PREFIX="$2"; shift 2 ;;
    --cert-days) CERT_DAYS="$2"; shift 2 ;;
    --export-dir) EXPORT_DIR="$2"; shift 2 ;;
    *) err "неизвестный аргумент: $1" ;;
  esac
done

[ -n "${GATEWAY_SAN}" ] || err "--gateway-san обязателен"
[ "${#CONNECTOR_IDS[@]}" -gt 0 ] || err "нужен хотя бы один --connector-id"
[ -n "${VAULT_TOKEN:-}" ] || err "VAULT_TOKEN не задан"
command -v jq >/dev/null 2>&1 || err "нужен jq"
command -v curl >/dev/null 2>&1 || err "нужен curl"

script_dir="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
# Приватные ключи не должны пережить скрипт даже при ошибке.
trap 'rm -rf "${work}"' EXIT
chmod 700 "${work}"

vault_read() {
  curl -sf -m 30 -H "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/${VAULT_KV_MOUNT}/data/$1"
}

# Vault KV v2 перезаписывает документ целиком, поэтому обновление одного
# свойства — это read-merge-write: иначе соседние секреты сервиса пропадут.
vault_patch() {
  local path="$1" payload="$2" current merged version
  current="$(vault_read "${path}" || echo '{"data":{"data":{},"metadata":{"version":0}}}')"
  version="$(echo "${current}" | jq '.data.metadata.version')"
  merged="$(echo "${current}" | jq --argjson patch "${payload}" \
    '{data: (.data.data + $patch), options: {cas: .data.metadata.version}}')"
  echo "${merged}" | curl -sf -m 30 -X POST \
    -H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json" \
    -d @- "${VAULT_ADDR}/v1/${VAULT_KV_MOUNT}/data/${path}" >/dev/null \
    || err "не удалось записать ${path} (версия ${version}; возможно, кто-то изменил секрет параллельно)"
}

echo "connector-cert-rotate: беру CA из ${CA_PATH}"
mkdir -p "${work}/pki/ca"
ca_json="$(vault_read "${CA_PATH}")" || err "CA не читается: ${CA_PATH}"
echo "${ca_json}" | jq -r '.data.data.ca_crt' > "${work}/pki/ca/ca.crt"
echo "${ca_json}" | jq -r '.data.data.ca_key' > "${work}/pki/ca/ca.key"
chmod 600 "${work}/pki/ca/ca.key"
[ -s "${work}/pki/ca/ca.crt" ] || err "в ${CA_PATH} нет ca_crt"

# Листовые выпускаются заново, CA переиспользуется: connector-pki.sh
# пропускает уже готовые компоненты и до-генерирует недостающие.
args=(--out-dir "${work}/pki" --gateway-san "${GATEWAY_SAN}" --cert-days "${CERT_DAYS}")
for id in "${CONNECTOR_IDS[@]}"; do
  args+=(--connector-id "${id}")
done
"${script_dir}/connector-pki.sh" "${args[@]}" >/dev/null

echo "connector-cert-rotate: обновляю сертификат gateway в ${GATEWAY_PATH}"
gateway_payload="$(jq -n \
  --rawfile cert "${work}/pki/gateway/server.crt" \
  --rawfile key "${work}/pki/gateway/server.key" \
  '{connector_gateway_tls_cert: $cert, connector_gateway_tls_key: $key}')"
vault_patch "${GATEWAY_PATH}" "${gateway_payload}"

for id in "${CONNECTOR_IDS[@]}"; do
  echo "connector-cert-rotate: обновляю сертификат connector '${id}'"
  # Только собственный сертификат сегмента: публичные CA и ключ проверки
  # лежат в общем ключе и при ротации листовых не меняются.
  payload="$(jq -n \
    --rawfile cert "${work}/pki/connectors/${id}/client.crt" \
    --rawfile key "${work}/pki/connectors/${id}/client.key" \
    '{connector_tls_cert: $cert, connector_tls_key: $key}')"
  vault_patch "${CONNECTOR_PREFIX}${id}" "${payload}"
done

if [ -n "${EXPORT_DIR}" ]; then
  mkdir -p "${EXPORT_DIR}"
  chmod 700 "${EXPORT_DIR}"
  cp -R "${work}/pki/." "${EXPORT_DIR}/"
  echo "connector-cert-rotate: PEM выгружены в ${EXPORT_DIR} (для агентов вне Kubernetes)"
  echo "connector-cert-rotate: удалите каталог после переноса"
fi

cat <<'TEXT'

connector-cert-rotate: готово. Дальше:
  * в Kubernetes — ExternalSecret подтянет новый материал (refreshInterval),
    reloader перезапустит поды; вмешательство не требуется;
  * вне Kubernetes — перенесите PEM из --export-dir и перезапустите сервис.

CA не менялся, поэтому старые сертификаты продолжают приниматься до
перезапуска: окна недоступности нет.
TEXT
