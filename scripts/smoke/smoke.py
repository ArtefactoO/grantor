"""Обвязка локального API-смоука grantor (docs/local-smoke.md).

Форжирование dev-сессий по GRANTOR_SESSION_SECRET dev-контура, вызовы API,
чтение Vault и проверки на target-системах через docker exec. Все секреты
здесь — dev-заглушки из docker-compose.yml и scripts/test-integration.sh,
к production отношения не имеют. Запуск — python3 без сторонних зависимостей.

Использование из сценария:

    from smoke import api, vault_read, wait_op, LOGIN, record
    code, body = api("admin", "POST", "/api/v1/connections", {...})
"""
import base64
import hashlib
import hmac
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

API = os.environ.get("SMOKE_API", "http://localhost:58082")
VAULT = os.environ.get("SMOKE_VAULT", "http://localhost:58200")
VAULT_TOKEN = os.environ.get("SMOKE_VAULT_TOKEN", "grantor-dev-root")
SECRET = os.environ.get("SMOKE_SESSION_SECRET",
                        "grantor-dev-session-secret-32bytes!").encode()

RESULTS_PATH = os.environ.get("SMOKE_RESULTS", "smoke-results.tsv")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge(role: str, sub: str | None = None, email: str | None = None) -> dict:
    """Подписанная cookie-сессия dev-контура (internal/auth Codec)."""
    sub = sub or f"smoke-{role}"
    email = email or f"{role}@grantor.dev"
    payload = {
        "sub": sub,
        "email": email,
        "role": role,
        "exp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200)),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    cookie = _b64u(raw) + "." + _b64u(hmac.new(SECRET, raw, hashlib.sha256).digest())
    csrf = hmac.new(SECRET, b"csrf:" + sub.encode(), hashlib.sha256).hexdigest()
    return {"cookie": cookie, "csrf": csrf}


SESSIONS = {r: forge(r) for r in ("admin", "operator", "viewer")}


def api(role, method, path, body=None, bearer=None, csrf=True, raw=False):
    """Вызов API: возвращает (status, parsed_json | text | bytes)."""
    req = urllib.request.Request(API + path, method=method)
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", "Bearer " + bearer)
    elif role:
        s = SESSIONS[role]
        req.add_header("Cookie", "grantor_session=" + s["cookie"])
        if csrf and method not in ("GET", "HEAD"):
            req.add_header("X-Grantor-CSRF", s["csrf"])
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        data = e.read()
        code = e.code
    if raw:
        return code, data
    try:
        return code, json.loads(data) if data else None
    except json.JSONDecodeError:
        return code, data.decode(errors="replace")


def vault_read(path, version=None):
    """KV v2 секрет без mount-префикса: (data, metadata) или (None, None)."""
    url = f"{VAULT}/v1/secret/data/{path}"
    if version:
        url += f"?version={version}"
    req = urllib.request.Request(url)
    req.add_header("X-Vault-Token", VAULT_TOKEN)
    try:
        with urllib.request.urlopen(req) as resp:
            d = json.loads(resp.read())
            return d["data"]["data"], d["data"]["metadata"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise


def wait_op(op_id, timeout=120, role="admin"):
    """Ждёт терминального статуса операции (терминальный — "success", не
    "succeeded"); возвращает объект операции."""
    terminal = {"success", "failed", "partial", "rejected", "cancelled", "superseded"}
    deadline = time.time() + timeout
    op = None
    while time.time() < deadline:
        code, op = api(role, "GET", f"/api/v1/operations/{op_id}")
        assert code == 200, (code, op)
        if op.get("status") in terminal:
            return op
        time.sleep(1.5)
    raise TimeoutError(f"operation {op_id} not terminal: {op and op.get('status')}")


def wait(cond, timeout=90, every=2, desc="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = cond()
        if v:
            return v
        time.sleep(every)
    raise TimeoutError(f"timeout waiting for {desc}")


def dx(container, *cmd):
    """docker exec; возвращает (returncode, stdout+stderr)."""
    p = subprocess.run(["docker", "exec", container, *cmd],
                       capture_output=True, text=True, timeout=120)
    return p.returncode, (p.stdout + p.stderr).strip()


# --- Логины на target: True == аутентификация принята целевой системой. ---

def login_postgres(user, password, db="appdb"):
    # Подключение по сети из соседнего контейнера: изнутри target-контейнера
    # 127.0.0.1 идёт по trust из дефолтного pg_hba и пароль не проверяется.
    code, out = dx("grantor-postgres-1", "env", f"PGPASSWORD={password}",
                   "psql", "-h", "target-postgres", "-U", user, "-d", db,
                   "-Atc", "select 1")
    return code == 0 and out.strip().endswith("1")


def login_mysql(user, password):
    code, out = dx("grantor-target-mysql-1", "mysql", f"-u{user}", f"-p{password}",
                   "-h", "127.0.0.1", "-N", "-e", "select 1")
    return code == 0 and "1" in out


def login_mongo(user, password, authdb="admin"):
    code, out = dx("grantor-target-mongo-1", "mongosh", "--quiet",
                   "-u", user, "-p", password, "--authenticationDatabase", authdb,
                   "--eval", "db.runCommand({ping:1}).ok")
    return code == 0 and out.strip().endswith("1")


def login_rabbitmq(user, password):
    code, _ = dx("grantor-target-rabbitmq-1",
                 "rabbitmqctl", "authenticate_user", user, password)
    return code == 0


def login_clickhouse(user, password):
    code, out = dx("grantor-target-clickhouse-1", "clickhouse-client",
                   "--user", user, "--password", password, "--query", "SELECT 1")
    return code == 0 and out.strip() == "1"


def login_kafka(user, password):
    code, _ = dx("grantor-target-redpanda-1", "rpk", "cluster", "info",
                 "-X", "brokers=localhost:9092", "-X", f"user={user}",
                 "-X", f"pass={password}", "-X", "sasl.mechanism=SCRAM-SHA-256")
    return code == 0


def login_redis(user, password):
    # PING не входит в @read, поэтому проба — читающая команда.
    code, out = dx("grantor-target-redis-1", "redis-cli", "--no-auth-warning",
                   "--user", user, "--pass", password, "GET", "smoke-probe")
    return code == 0 and "WRONGPASS" not in out and "NOPERM" not in out \
        and "invalid" not in out.lower()


LOGIN = {
    "postgres": login_postgres,
    "mysql": login_mysql,
    "mongodb": login_mongo,
    "rabbitmq": login_rabbitmq,
    "clickhouse": login_clickhouse,
    "kafka": login_kafka,
    "redis": login_redis,
}


def meta_sql(query):
    """SQL к metadata-базе стенда — только для смоук-форсажа (purge_after)."""
    p = subprocess.run(["docker", "exec", "grantor-postgres-1", "psql",
                        "-U", "grantor", "-d", "grantor", "-Atc", query],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).strip()


def record(num, name, ok, detail=""):
    line = f"{num}\t{'PASS' if ok else 'FAIL'}\t{name}\t{detail}"
    print(line, flush=True)
    with open(RESULTS_PATH, "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    code, me = api("admin", "GET", "/auth/me")
    print("auth/me:", code, me)
