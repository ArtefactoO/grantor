#!/usr/bin/env bash
# Интеграционные тесты: поднимает ephemeral PostgreSQL и Vault в Docker,
# прогоняет `go test -tags integration` в контейнере в той же сети и всё
# убирает за собой. Локальный toolchain не используется.
set -euo pipefail

cd "$(dirname "$0")/.."

# TEST_ID (опционально) изолирует имена сети и контейнеров этого прогона,
# чтобы несколько параллельных прогонов integration на одном Docker-хосте не
# сталкивались (например, при одновременной разработке нескольких adapters в
# разных worktree). Пусто = прежние имена (grantor-test-*), полная обратная
# совместимость; TEST_ID=ch → grantor-test-ch-*.
SFX="${TEST_ID:+-$TEST_ID}"

NET="grantor-test${SFX}-net"
PG="grantor-test${SFX}-pg"
TARGET_PG="grantor-test${SFX}-target-pg"
VAULT="grantor-test${SFX}-vault"
YOPASS="grantor-test${SFX}-yopass"
MEMCACHED="grantor-test${SFX}-memcached"
MONGO="grantor-test${SFX}-mongo"
MONGO_RS="grantor-test${SFX}-mongo-rs"
MYSQL="grantor-test${SFX}-mysql"
RABBITMQ="grantor-test${SFX}-rabbitmq"
LDAP="grantor-test${SFX}-ldap"
CLICKHOUSE="grantor-test${SFX}-clickhouse"
REDPANDA="grantor-test${SFX}-redpanda"
REDIS="grantor-test${SFX}-redis"
REDIS_NOAUTH="grantor-test${SFX}-redis-noauth"
# GRANTOR_TEST_CLUSTERS=1 включает opt-in проверку live-кластеров: к трём
# «кластерным» движкам добавляется по второму узлу (имена ниже), первые узлы
# становятся членами кластеров, а Go-тестам передаются
# GRANTOR_TEST_{RABBITMQ,KAFKA,CLICKHOUSE}_CLUSTER=1. По умолчанию (пусто)
# вторые узлы не поднимаются, дополнительное время прогона — ноль, а
# cluster-тесты в Go делают t.Skip.
CLUSTERS="${GRANTOR_TEST_CLUSTERS:-}"
RABBITMQ_NODE2="grantor-test${SFX}-rabbitmq-2"
CLICKHOUSE_NODE2="grantor-test${SFX}-clickhouse-2"
REDPANDA_NODE2="grantor-test${SFX}-redpanda-2"
GO_IMAGE="${GO_IMAGE:-golang:1.26}"
PG_IMAGE="${PG_IMAGE:-postgres:16}"
# Metadata-PostgreSQL (metadata/jobs/audit самого grantor).
PG_USER="${PG_USER:-postgres}"
PG_PASS="${PG_PASS:-grantor}"
PG_DB="${PG_DB:-grantor}"
# «Целевой» PostgreSQL, которым управляет postgres adapter.
TARGET_PG_USER="${TARGET_PG_USER:-grantor_admin}"
TARGET_PG_PASS="${TARGET_PG_PASS:-grantor-target}"
TARGET_PG_DB="${TARGET_PG_DB:-postgres}"
VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.20}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:7}"
MONGO_USER="${MONGO_USER:-root}"
MONGO_PASS="${MONGO_PASS:-grantor-mongo}"
MYSQL_IMAGE="${MYSQL_IMAGE:-mysql:8.4}"
MYSQL_PASS="${MYSQL_PASS:-grantor-mysql}"
RABBITMQ_IMAGE="${RABBITMQ_IMAGE:-rabbitmq:3.13-management}"
RABBITMQ_USER="${RABBITMQ_USER:-grantor}"
RABBITMQ_PASS="${RABBITMQ_PASS:-grantor-rabbit}"
CLICKHOUSE_IMAGE="${CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:24.8}"
CLICKHOUSE_USER="${CLICKHOUSE_USER:-grantor}"
CLICKHOUSE_PASS="${CLICKHOUSE_PASS:-grantor-clickhouse}"
# osixia/openldap выбран вместо bitnami/openldap: тег bitnami/openldap:2.6
# удалён с docker.io (миграция Bitnami в Secure Images), а osixia стабильно
# бутится с базой из LDAP_DOMAIN и доступен под arm64.
LDAP_IMAGE="${LDAP_IMAGE:-osixia/openldap:1.5.0}"
LDAP_ADMIN_PASS="${LDAP_ADMIN_PASS:-grantor-ldap}"
LDAP_BASE_DN="dc=grantor,dc=test"
LDAP_BIND_DN="cn=admin,$LDAP_BASE_DN"
# Kafka user SCRAM API (KIP-554: Describe/AlterUserScramCredentials), которым
# kafka adapter управляет учётками, появился в Redpanda только в v25.2 —
# более старые образы отвечают UNSUPPORTED_VERSION ("broker is too old").
REDPANDA_IMAGE="${REDPANDA_IMAGE:-redpandadata/redpanda:v25.2.9}"
KAFKA_USER="${KAFKA_USER:-grantor}"
KAFKA_PASS="${KAFKA_PASS:-grantor-redpanda}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
REDIS_PASS="${REDIS_PASS:-grantor-redis}"
CACHE_VOLUME="${CACHE_VOLUME:-grantor-build-cache}"
VAULT_TOKEN="${VAULT_TOKEN:-grantor-test-root}"
# Переопределяемые параметры прогона, например:
#   GO_TEST_PKGS=./internal/jobs GO_TEST_FLAGS=-v make test-integration
GO_TEST_PKGS="${GO_TEST_PKGS:-./...}"
GO_TEST_FLAGS="${GO_TEST_FLAGS:-}"

# wait_for <name> <tries> <delay> <probe-cmd...>: опрашивает probe-cmd до
# <tries> раз с паузой <delay>с между попытками. Успех (probe вернул 0) —
# возврат; исчерпание попыток — "<name> did not become ready" в stderr и
# exit 1 (как в исходных wait-петлях). Вывод probe подавляется; составной
# probe с pipe передавать одним аргументом через `bash -c '...'`.
wait_for() {
  local name="$1" tries="$2" delay="$3"
  shift 3
  local i
  for i in $(seq 1 "$tries"); do
    "$@" >/dev/null 2>&1 && return 0
    [ "$i" = "$tries" ] && { echo "$name did not become ready" >&2; exit 1; }
    sleep "$delay"
  done
}

cleanup() {
  docker rm -f "$PG" "$TARGET_PG" "$VAULT" "$YOPASS" "$MEMCACHED" "$MONGO" "$MONGO_RS" "$MYSQL" \
    "$RABBITMQ" "$RABBITMQ_NODE2" "$CLICKHOUSE" "$CLICKHOUSE_NODE2" "$LDAP" \
    "$REDPANDA" "$REDPANDA_NODE2" "$REDIS" "$REDIS_NOAUTH" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null

docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB="$PG_DB" \
  "$PG_IMAGE" >/dev/null

# Отдельный «целевой» PostgreSQL, которым управляет postgres adapter в
# integration-тестах (metadata-база и цель управления не смешиваются).
docker run -d --name "$TARGET_PG" --network "$NET" \
  -e POSTGRES_USER="$TARGET_PG_USER" -e POSTGRES_PASSWORD="$TARGET_PG_PASS" \
  -e POSTGRES_DB="$TARGET_PG_DB" \
  "$PG_IMAGE" >/dev/null

docker run -d --name "$VAULT" --network "$NET" \
  -e VAULT_DEV_ROOT_TOKEN_ID="$VAULT_TOKEN" \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  "$VAULT_IMAGE" >/dev/null

docker run -d --name "$MEMCACHED" --network "$NET" memcached:1.6-alpine >/dev/null
docker run -d --name "$YOPASS" --network "$NET" jhaals/yopass:latest \
  --memcached="$MEMCACHED:11211" --port 1337 >/dev/null

# «Целевой» MongoDB для mongodb adapter: standalone (с auth) и одноузловой
# replica set (без auth, только для проверки определения топологии).
docker run -d --name "$MONGO" --network "$NET" \
  -e MONGO_INITDB_ROOT_USERNAME="$MONGO_USER" -e MONGO_INITDB_ROOT_PASSWORD="$MONGO_PASS" \
  "$MONGO_IMAGE" >/dev/null
docker run -d --name "$MONGO_RS" --network "$NET" \
  "$MONGO_IMAGE" --replSet rs0 --bind_ip_all >/dev/null

# «Целевой» MySQL для mysql adapter (standalone).
docker run -d --name "$MYSQL" --network "$NET" \
  -e MYSQL_ROOT_PASSWORD="$MYSQL_PASS" -e MYSQL_ROOT_HOST=% \
  "$MYSQL_IMAGE" >/dev/null

# «Целевой» RabbitMQ для rabbitmq adapter (по умолчанию standalone). guest по
# умолчанию доступен только с localhost, поэтому администратора создаём через
# RABBITMQ_DEFAULT_USER/PASS. Hostname и Erlang cookie заданы всегда (образ
# лишь предупреждает "Overriding Erlang cookie", боту узла это не мешает):
# при GRANTOR_TEST_CLUSTERS=1 к этому узлу присоединяется второй
# (join_cluster требует общий cookie и предсказуемое имя rabbit@<hostname>).
RABBITMQ_COOKIE="grantor-test-cluster-cookie"
docker run -d --name "$RABBITMQ" --network "$NET" --hostname "$RABBITMQ" \
  -e RABBITMQ_DEFAULT_USER="$RABBITMQ_USER" \
  -e RABBITMQ_DEFAULT_PASS="$RABBITMQ_PASS" \
  -e RABBITMQ_ERLANG_COOKIE="$RABBITMQ_COOKIE" \
  "$RABBITMQ_IMAGE" >/dev/null

# «Целевой» ClickHouse (standalone) для clickhouse adapter. Админ создаётся
# через CLICKHOUSE_USER/PASSWORD, а CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1
# включает ему access management (управление пользователями/ролями/грантами).
docker run -d --name "$CLICKHOUSE" --network "$NET" \
  -e CLICKHOUSE_USER="$CLICKHOUSE_USER" \
  -e CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASS" \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  "$CLICKHOUSE_IMAGE" >/dev/null

# OpenLDAP для directory provider offboarding-детекции (internal/directory):
# база dc=grantor,dc=test создаётся образом из LDAP_DOMAIN; пользователи
# сидируются ldapadd-ом ниже (active / с disabled-атрибутом / отсутствующий
# субъект проверяется отсутствием записи).
docker run -d --name "$LDAP" --network "$NET" \
  -e LDAP_ORGANISATION="Grantor Test" \
  -e LDAP_DOMAIN=grantor.test \
  -e LDAP_ADMIN_PASSWORD="$LDAP_ADMIN_PASS" \
  "$LDAP_IMAGE" >/dev/null

# «Целевой» Redis (standalone) для redis adapter. requirepass делает
# пользователя default admin-учёткой с +@all — именно ей adapter управляет
# ACL остальных пользователей.
docker run -d --name "$REDIS" --network "$NET" \
  "$REDIS_IMAGE" redis-server --requirepass "$REDIS_PASS" >/dev/null
docker run -d --name "$REDIS_NOAUTH" --network "$NET" "$REDIS_IMAGE" >/dev/null

# «Целевая» Redpanda для kafka adapter (по умолчанию одноузловая; SASL включён,
# admin-пользователь — superuser grantor, создаётся после старта через rpk).
# sasl_mechanisms=[SCRAM,PLAIN] включает оба механизма на одном PLAINTEXT-
# листенере: SCRAM-путь (существующий lifecycle-тест) и PLAIN-путь (новый тест
# ValidateConnection+discovery) аутентифицируются одной admin-учёткой, разными
# механизмами — так проверяется per-connection выбор SASL. Apache Kafka
# покрывается тем же adapter по протоколу (см. пакет kafka). RPC-адрес объявлен
# всегда (для standalone это no-op): при GRANTOR_TEST_CLUSTERS=1 второй брокер
# присоединяется через --seeds <этот узел>:33145 и должен уметь достучаться до
# его RPC по DNS-имени.
docker run -d --name "$REDPANDA" --network "$NET" \
  "$REDPANDA_IMAGE" \
  redpanda start --mode dev-container --smp 1 --memory 512M --overprovisioned \
  --kafka-addr PLAINTEXT://0.0.0.0:9092 \
  --advertise-kafka-addr PLAINTEXT://"$REDPANDA":9092 \
  --rpc-addr 0.0.0.0:33145 \
  --advertise-rpc-addr "$REDPANDA":33145 \
  --set redpanda.enable_sasl=true \
  --set "redpanda.sasl_mechanisms=[\"SCRAM\",\"PLAIN\"]" \
  --set "redpanda.superusers=[\"$KAFKA_USER\"]" >/dev/null

# --- Live-кластеры (opt-in, GRANTOR_TEST_CLUSTERS=1): boot вторых узлов ---
# Вторые узлы стартуют сразу после первых, чтобы их boot шёл параллельно
# базовым wait-петлям; join/проверки — отдельным блоком ниже, когда первые
# узлы уже готовы. По умолчанию блок пропускается целиком.
if [ -n "$CLUSTERS" ]; then
  echo "clusters gate is on: booting second rabbitmq/redpanda/clickhouse nodes..."

  # Второй узел RabbitMQ: тот же cookie, что у первого; hostname задаёт
  # предсказуемое имя узла rabbit@<container>. DEFAULT_USER/PASS нужны только
  # до join (после join_cluster узел принимает учётки кластера).
  docker run -d --name "$RABBITMQ_NODE2" --network "$NET" --hostname "$RABBITMQ_NODE2" \
    -e RABBITMQ_DEFAULT_USER="$RABBITMQ_USER" \
    -e RABBITMQ_DEFAULT_PASS="$RABBITMQ_PASS" \
    -e RABBITMQ_ERLANG_COOKIE="$RABBITMQ_COOKIE" \
    "$RABBITMQ_IMAGE" >/dev/null

  # Второй брокер Redpanda присоединяется к первому через --seeds (node ID
  # выдаст кластер). SASL-настройки повторены для симметрии: это cluster-level
  # конфиг, join унаследует его и без них.
  docker run -d --name "$REDPANDA_NODE2" --network "$NET" \
    "$REDPANDA_IMAGE" \
    redpanda start --mode dev-container --smp 1 --memory 512M --overprovisioned \
    --kafka-addr PLAINTEXT://0.0.0.0:9092 \
    --advertise-kafka-addr PLAINTEXT://"$REDPANDA_NODE2":9092 \
    --rpc-addr 0.0.0.0:33145 \
    --advertise-rpc-addr "$REDPANDA_NODE2":33145 \
    --seeds "$REDPANDA":33145 \
    --set redpanda.enable_sasl=true \
    --set "redpanda.sasl_mechanisms=[\"SCRAM\",\"PLAIN\"]" \
    --set "redpanda.superusers=[\"$KAFKA_USER\"]" >/dev/null

  # Второй ClickHouse — обычный standalone-сервер: «кластер» здесь только
  # определение remote_servers (grantor_cluster из двух хостов), которое ниже
  # записывается в config.d обоих узлов. Это detection-level кластеризация
  # (system.clusters), без Keeper и Replicated-таблиц: adapter детектирует
  # топологию по system.clusters, ON CLUSTER DDL остаётся вне scope.
  docker run -d --name "$CLICKHOUSE_NODE2" --network "$NET" \
    -e CLICKHOUSE_USER="$CLICKHOUSE_USER" \
    -e CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASS" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    "$CLICKHOUSE_IMAGE" >/dev/null
fi

echo "waiting for postgres..."
wait_for "postgres" 60 1 docker exec "$PG" pg_isready -U "$PG_USER" -d "$PG_DB"

echo "waiting for target postgres..."
wait_for "target postgres" 60 1 \
  docker exec "$TARGET_PG" pg_isready -U "$TARGET_PG_USER" -d "$TARGET_PG_DB"

echo "waiting for vault..."
wait_for "vault" 60 1 docker exec -e VAULT_ADDR=http://127.0.0.1:8200 "$VAULT" vault status

echo "waiting for mongo..."
wait_for "mongo" 60 1 docker exec "$MONGO" mongosh --quiet \
  -u "$MONGO_USER" -p "$MONGO_PASS" --authenticationDatabase admin \
  --eval 'db.runCommand({ping:1}).ok'

echo "initializing mongo replica set..."
wait_for "mongo-rs" 60 1 \
  docker exec "$MONGO_RS" mongosh --quiet --eval 'db.runCommand({ping:1}).ok'
docker exec "$MONGO_RS" mongosh --quiet \
  --eval "rs.initiate({_id:'rs0',members:[{_id:0,host:'$MONGO_RS:27017'}]})" >/dev/null 2>&1 || true
for i in $(seq 1 30); do
  docker exec "$MONGO_RS" mongosh --quiet --eval 'db.hello().isWritablePrimary' 2>/dev/null | grep -q true && break
  sleep 1
done

echo "waiting for mysql..."
wait_for "mysql" 90 1 docker exec "$MYSQL" mysqladmin ping -uroot -p"$MYSQL_PASS" --silent

# RabbitMQ загружается медленно: сначала ждём готовности узла (быстрый exec без
# зависимости от curl), затем опрашиваем Management API curl-ом до ~90s.
echo "waiting for rabbitmq node..."
wait_for "rabbitmq node" 60 1 \
  docker exec "$RABBITMQ" rabbitmq-diagnostics -q check_port_connectivity
echo "waiting for rabbitmq management api..."
wait_for "rabbitmq management api" 45 2 \
  docker run --rm --network "$NET" "$GO_IMAGE" \
    curl -fsS -u "$RABBITMQ_USER:$RABBITMQ_PASS" "http://$RABBITMQ:15672/api/overview"

echo "waiting for clickhouse..."
wait_for "clickhouse" 90 1 \
  docker exec "$CLICKHOUSE" clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASS" \
    --query 'SELECT 1'

echo "waiting for redis..."
wait_for "redis" 60 1 \
  bash -c "docker exec \"$REDIS\" redis-cli -a \"$REDIS_PASS\" --no-auth-warning ping | grep -q PONG"

wait_for "redis-noauth" 60 1 docker exec "$REDIS_NOAUTH" redis-cli ping

echo "waiting for openldap..."
wait_for "openldap" 60 1 \
  docker exec "$LDAP" ldapsearch -x -H ldap://localhost:389 \
    -D "$LDAP_BIND_DN" -w "$LDAP_ADMIN_PASS" -b "$LDAP_BASE_DN" -s base

# Сидируем пользователей каталога: alice — активная, carol — с атрибутом
# блокировки (employeeType=disabled, под GRANTOR_TEST-фильтр disabled),
# bob@grantor.test намеренно НЕ создаётся (сценарий missing/offboarded).
echo "seeding openldap users..."
docker exec -i "$LDAP" ldapadd -x -H ldap://localhost:389 \
  -D "$LDAP_BIND_DN" -w "$LDAP_ADMIN_PASS" >/dev/null <<LDIF
dn: ou=people,$LDAP_BASE_DN
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,$LDAP_BASE_DN
objectClass: inetOrgPerson
uid: alice
cn: Alice Active
sn: Active
mail: alice@grantor.test

dn: uid=carol,ou=people,$LDAP_BASE_DN
objectClass: inetOrgPerson
uid: carol
cn: Carol Disabled
sn: Disabled
mail: carol@grantor.test
employeeType: disabled
LDIF

# Redpanda: Kafka API требует SASL с самого старта, поэтому готовность узла
# проверяем через admin API (rpk cluster health, в dev-container без
# аутентификации), затем создаём admin SCRAM-пользователя и убеждаемся, что
# Kafka API с SASL/SCRAM реально отвечает этой учёткой.
echo "waiting for redpanda..."
wait_for "redpanda" 60 1 \
  bash -c "docker exec \"$REDPANDA\" rpk cluster health | grep -q 'Healthy:.*true'"
docker exec "$REDPANDA" rpk security user create "$KAFKA_USER" -p "$KAFKA_PASS" >/dev/null
echo "waiting for redpanda sasl kafka api..."
wait_for "redpanda sasl kafka api" 30 1 \
  docker exec "$REDPANDA" rpk cluster info -X brokers=localhost:9092 \
    -X user="$KAFKA_USER" -X pass="$KAFKA_PASS" -X sasl.mechanism=SCRAM-SHA-256

# --- Live-кластеры (opt-in, GRANTOR_TEST_CLUSTERS=1): join и проверки ---
# К этому моменту первые узлы готовы (wait-петли выше), вторые узлы бутятся
# с самого старта. Каждый движок доводится до состояния «кластер реально
# виден с первого узла», после чего Go-тесты получают
# GRANTOR_TEST_{RABBITMQ,KAFKA,CLICKHOUSE}_CLUSTER=1 (см. переменные ниже).
# Существующие standalone-тесты этих движков учитывают те же переменные
# (ожидаемая топология меняется на cluster / проверка пропускается).
RABBITMQ_CLUSTER_READY=""
KAFKA_CLUSTER_READY=""
CLICKHOUSE_CLUSTER_READY=""
if [ -n "$CLUSTERS" ]; then
  # RabbitMQ: дождаться бута второго узла, присоединить его к первому
  # (stop_app -> join_cluster -> start_app), затем убедиться, что
  # Management API первого узла видит оба узла в /api/nodes.
  echo "waiting for rabbitmq node 2..."
  wait_for "rabbitmq node 2" 60 1 \
    docker exec "$RABBITMQ_NODE2" rabbitmq-diagnostics -q check_running
  echo "joining rabbitmq node 2 to rabbit@$RABBITMQ..."
  docker exec "$RABBITMQ_NODE2" rabbitmqctl -q stop_app
  docker exec "$RABBITMQ_NODE2" rabbitmqctl -q join_cluster "rabbit@$RABBITMQ"
  docker exec "$RABBITMQ_NODE2" rabbitmqctl -q start_app
  echo "waiting for rabbitmq cluster (2 nodes in /api/nodes)..."
  for i in $(seq 1 45); do
    docker run --rm --network "$NET" \
      -e U="$RABBITMQ_USER" -e P="$RABBITMQ_PASS" "$GO_IMAGE" \
      sh -c "curl -fsS -u \"\$U:\$P\" http://$RABBITMQ:15672/api/nodes | grep -qF 'rabbit@$RABBITMQ_NODE2'" \
      >/dev/null 2>&1 && break
    [ "$i" = 45 ] && { echo "rabbitmq cluster did not reach 2 nodes" >&2; exit 1; }
    sleep 2
  done
  RABBITMQ_CLUSTER_READY=1

  # Redpanda: второй брокер присоединяется сам (--seeds); ждём, пока Kafka
  # Metadata первого узла (rpk cluster info под SASL) не вернёт 2 брокера —
  # ровно то, что увидит kafka adapter при Discover.
  echo "waiting for redpanda cluster (2 brokers in metadata)..."
  for i in $(seq 1 60); do
    n="$(docker exec "$REDPANDA" rpk cluster info -X brokers=localhost:9092 \
      -X user="$KAFKA_USER" -X pass="$KAFKA_PASS" -X sasl.mechanism=SCRAM-SHA-256 2>/dev/null |
      grep -cE '^[0-9]+\*?[[:space:]]')" || n=0
    [ "${n:-0}" -ge 2 ] && break
    [ "$i" = 60 ] && { echo "redpanda cluster did not reach 2 brokers" >&2; exit 1; }
    sleep 1
  done
  KAFKA_CLUSTER_READY=1

  # ClickHouse: дождаться второго сервера, записать определение
  # remote_servers (grantor_cluster: первый узел — локальная реплика,
  # второй — удалённая) в config.d обоих узлов и перечитать конфиг.
  # system.clusters на первом узле после этого показывает multi-host
  # кластер -> adapter детектирует topology=cluster.
  echo "waiting for clickhouse node 2..."
  wait_for "clickhouse node 2" 90 1 \
    docker exec "$CLICKHOUSE_NODE2" clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASS" \
      --query 'SELECT 1'
  echo "writing clickhouse remote_servers config (grantor_cluster)..."
  for node in "$CLICKHOUSE" "$CLICKHOUSE_NODE2"; do
    docker exec -i "$node" sh -c 'cat > /etc/clickhouse-server/config.d/grantor-test-cluster.xml' <<XML
<clickhouse>
  <remote_servers>
    <grantor_cluster>
      <shard>
        <replica><host>$CLICKHOUSE</host><port>9000</port></replica>
      </shard>
      <shard>
        <replica><host>$CLICKHOUSE_NODE2</host><port>9000</port></replica>
      </shard>
    </grantor_cluster>
  </remote_servers>
</clickhouse>
XML
    # Форсируем перечитывание; при недоступности SYSTEM RELOAD CONFIG сервер
    # и сам перечитает config.d по watcher-у — ниже это добирает wait-петля.
    docker exec "$node" clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASS" \
      --query 'SYSTEM RELOAD CONFIG' >/dev/null 2>&1 || true
  done
  echo "waiting for clickhouse cluster (2 hosts in system.clusters)..."
  for i in $(seq 1 45); do
    n="$(docker exec "$CLICKHOUSE" clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASS" \
      --query "SELECT count() FROM system.clusters WHERE cluster = 'grantor_cluster'" 2>/dev/null)" || n=0
    [ "${n:-0}" -ge 2 ] && break
    [ "$i" = 45 ] && { echo "clickhouse cluster did not appear in system.clusters" >&2; exit 1; }
    sleep 1
  done
  CLICKHOUSE_CLUSTER_READY=1
fi

# Packages share the same mutable target engines (including the connection
# admin credential). Running packages in parallel makes one package observe
# another package between create/drop or password rotate/restore. `-p 1`
# serializes packages while `-race` still exercises goroutine concurrency
# inside every package.
docker run --rm --network "$NET" \
  -v "$PWD":/src -w /src \
  -v "$CACHE_VOLUME":/cache \
  -e GOMODCACHE=/cache/gomod -e GOCACHE=/cache/gobuild \
  -e GRANTOR_TEST_DB_DSN="postgres://$PG_USER:$PG_PASS@$PG:5432/$PG_DB?sslmode=disable" \
  -e GRANTOR_TEST_TARGET_PG_DSN="postgres://$TARGET_PG_USER:$TARGET_PG_PASS@$TARGET_PG:5432/$TARGET_PG_DB?sslmode=disable" \
  -e GRANTOR_TEST_VAULT_ADDR="http://$VAULT:8200" \
  -e GRANTOR_TEST_VAULT_TOKEN="$VAULT_TOKEN" \
  -e GRANTOR_TEST_VAULT_MOUNT=secret \
  -e GRANTOR_TEST_YOPASS_ADDR="http://$YOPASS:1337" \
  -e GRANTOR_TEST_MONGO_URI="mongodb://$MONGO_USER:$MONGO_PASS@$MONGO:27017/?authSource=admin" \
  -e GRANTOR_TEST_MONGO_RS_URI="mongodb://$MONGO_RS:27017/?replicaSet=rs0&directConnection=true" \
  -e GRANTOR_TEST_MYSQL_DSN="root:$MYSQL_PASS@tcp($MYSQL:3306)/" \
  -e GRANTOR_TEST_RABBITMQ_URL="http://$RABBITMQ_USER:$RABBITMQ_PASS@$RABBITMQ:15672" \
  -e GRANTOR_TEST_CLICKHOUSE_URL="http://$CLICKHOUSE_USER:$CLICKHOUSE_PASS@$CLICKHOUSE:8123" \
  -e GRANTOR_TEST_LDAP_URL="ldap://$LDAP:389" \
  -e GRANTOR_TEST_LDAP_BIND_DN="$LDAP_BIND_DN" \
  -e GRANTOR_TEST_LDAP_BIND_PASSWORD="$LDAP_ADMIN_PASS" \
  -e GRANTOR_TEST_LDAP_BASE_DN="$LDAP_BASE_DN" \
  -e GRANTOR_TEST_KAFKA_BROKER="$REDPANDA:9092" \
  -e GRANTOR_TEST_KAFKA_USER="$KAFKA_USER" \
  -e GRANTOR_TEST_KAFKA_PASS="$KAFKA_PASS" \
  -e GRANTOR_TEST_KAFKA_PLAIN=1 \
  -e GRANTOR_TEST_REDIS_ADDR="$REDIS:6379" \
  -e GRANTOR_TEST_REDIS_PASSWORD="$REDIS_PASS" \
  -e GRANTOR_TEST_REDIS_NOAUTH_ADDR="$REDIS_NOAUTH:6379" \
  -e GRANTOR_TEST_RABBITMQ_CLUSTER="$RABBITMQ_CLUSTER_READY" \
  -e GRANTOR_TEST_KAFKA_CLUSTER="$KAFKA_CLUSTER_READY" \
  -e GRANTOR_TEST_CLICKHOUSE_CLUSTER="$CLICKHOUSE_CLUSTER_READY" \
  "$GO_IMAGE" go test -p 1 -race -count=1 -tags integration $GO_TEST_FLAGS $GO_TEST_PKGS
