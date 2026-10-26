#!/usr/bin/env python3
"""Настройка локального Authentik под grantor.

Dev-контур: заводит всё, что нужно для входа в grantor и для работы с
каталогом, чтобы `make up` давал рабочий стенд без ручных шагов в UI
Authentik.

Что создаётся:

* группы grantor-admins / grantor-operators / grantor-viewers — по ним
  grantor выдаёт роли (GRANTOR_RBAC_*_GROUPS);
* четыре человека, разложенные по этим группам, плюс один выключенный —
  для проверки offboarding-детекции и того, что выключенный не получает
  доступ;
* scope mapping groups. Authentik НЕ отдаёт claim groups из коробки:
  среди дефолтных property mappings его нет, и без своего маппинга роль
  по группе не определить;
* OIDC-провайдер и приложение для входа. Провайдеру обязательно задаётся
  signing key: без него Authentik подписывает id_token алгоритмом HS256,
  а grantor принимает только RS256 — вход падал бы на проверке подписи;
Каталог (импорт принципалов и поллинг статусов) отдельной настройки не
требует: grantor обращается к самому API Authentik, поэтому LDAP-провайдер
и outpost стенду не нужны.

Скрипт идемпотентен: повторный запуск не создаёт дублей и не меняет то,
что уже настроено. Это важно, потому что он выполняется при каждом
подъёме стека.

Только для локального контура. Пароли и токены здесь стендовые и заданы
явно; в production Authentik разворачивается отдельно, а секреты приходят
из Vault.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("AUTHENTIK_URL", "http://authentik-server:9000")
TOKEN = os.environ.get("AUTHENTIK_TOKEN", "grantor-local-bootstrap-token")
API = BASE.rstrip("/") + "/api/v3"

# Пароль стендовых учёток. Один на всех: контур локальный, и запоминать
# четыре разных незачем.
USER_PASSWORD = os.environ.get("GRANTOR_LOCAL_USER_PASSWORD", "grantor")

# Роли -> группы. Имена совпадают с GRANTOR_RBAC_*_GROUPS в docker-compose.
GROUPS = ["grantor-admins", "grantor-operators", "grantor-viewers"]

# Стендовые люди: (логин, отображаемое имя, группа, активен).
# Выключенный нужен, чтобы на стенде было на ком проверять и
# offboarding-детекцию, и отказ во входе.
USERS = [
    ("admin", "Админ Грантора", "grantor-admins", True),
    ("operator", "Оператор Грантора", "grantor-operators", True),
    ("viewer", "Наблюдатель Грантора", "grantor-viewers", True),
    ("blocked", "Заблокированный Сотрудник", "grantor-operators", False),
]

REDIRECT_URI = os.environ.get(
    "GRANTOR_OIDC_REDIRECT_URL", "http://localhost:58080/auth/callback"
)


def call(method: str, path: str, body: dict | None = None) -> tuple[dict, int]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return (json.loads(raw) if raw else {}), resp.status
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()[:400]}, e.code


def wait_ready(attempts: int = 60) -> None:
    """Ждёт готовности Authentik.

    Проверяется не только /-/health/ready/, но и работоспособность самого
    API: health отвечает 200 раньше, чем становятся доступны миграции и
    записи по умолчанию, и запись, отправленная в этот промежуток, падает
    без внятной ошибки. Поэтому ждём успешного чтения через API.
    """
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(BASE + "/-/health/ready/", timeout=5) as r:
                ready = r.status == 200
        except Exception:  # noqa: BLE001 — любая ошибка означает «ещё не готов»
            ready = False
        if ready:
            probe, code = call("GET", "/core/groups/?page_size=1")
            if code == 200 and "results" in probe:
                return
        time.sleep(5)
    sys.exit("authentik-bootstrap: authentik is not ready")


def find(path: str) -> dict | None:
    d, _ = call("GET", path)
    results = d.get("results") or []
    return results[0] if results else None


def ensure_groups() -> dict[str, str]:
    out = {}
    for name in GROUPS:
        existing = find(f"/core/groups/?name={name}")
        if existing:
            out[name] = existing["pk"]
            continue
        created, code = call("POST", "/core/groups/", {"name": name})
        if code >= 300 or "pk" not in created:
            sys.exit(f"authentik-bootstrap: create group {name}: {created}")
        out[name] = created["pk"]
    return out


def ensure_users(groups: dict[str, str]) -> None:
    for username, display, group, active in USERS:
        email = f"{username}@grantor.dev"
        existing = find(f"/core/users/?username={username}")
        if existing:
            pk = existing["pk"]
        else:
            created, code = call(
                "POST",
                "/core/users/",
                {
                    "username": username,
                    "name": display,
                    "email": email,
                    "is_active": active,
                    "type": "internal",
                },
            )
            if code >= 300:
                sys.exit(f"authentik-bootstrap: create user {username}: {created}")
            pk = created["pk"]
            # Пароль задаётся отдельным вызовом: в создании его не передать.
            call("POST", f"/core/users/{pk}/set_password/", {"password": USER_PASSWORD})
        call("POST", f"/core/groups/{groups[group]}/add_user/", {"pk": pk})


def ensure_groups_scope() -> str:
    """Scope mapping, отдающий claim groups. Своё, потому что среди дефолтных
    property mappings Authentik такого нет."""
    existing = find("/propertymappings/provider/scope/?scope_name=groups")
    if existing:
        return existing["pk"]
    created, code = call(
        "POST",
        "/propertymappings/provider/scope/",
        {
            "name": "grantor groups",
            "scope_name": "groups",
            "description": "Группы пользователя для маппинга ролей grantor",
            "expression": "return [group.name for group in request.user.ak_groups.all()]",
        },
    )
    if code >= 300:
        sys.exit(f"authentik-bootstrap: create groups scope: {created}")
    return created["pk"]


def signing_key() -> str | None:
    """RSA-ключ подписи id_token. Без него Authentik подписывает HS256, и
    grantor отклоняет токен: он принимает только RS256."""
    d, _ = call("GET", "/crypto/certificatekeypairs/?page_size=50")
    for c in d.get("results", []):
        if c.get("private_key_available"):
            return c["pk"]
    return None


def ensure_oidc(groups_scope: str) -> None:
    if find("/providers/oauth2/?name=grantor-oidc"):
        return
    auth_flow = find("/flows/instances/?slug=default-provider-authorization-implicit-consent")
    inval_flow = find("/flows/instances/?slug=default-provider-invalidation-flow")
    scopes, _ = call("GET", "/propertymappings/provider/scope/?page_size=50")
    wanted = {"openid", "profile", "email"}
    mappings = [m["pk"] for m in scopes.get("results", []) if m["scope_name"] in wanted]
    mappings.append(groups_scope)

    provider, code = call(
        "POST",
        "/providers/oauth2/",
        {
            "name": "grantor-oidc",
            "authorization_flow": auth_flow["pk"],
            "invalidation_flow": inval_flow["pk"],
            "client_type": "confidential",
            "client_id": os.environ.get("GRANTOR_OIDC_CLIENT_ID", "grantor"),
            "client_secret": os.environ.get(
                "GRANTOR_OIDC_CLIENT_SECRET", "grantor-local-oidc-secret"
            ),
            "redirect_uris": [{"matching_mode": "strict", "url": REDIRECT_URI}],
            "property_mappings": mappings,
            "signing_key": signing_key(),
            # sub = логин. Логин в AD (sAMAccountName) не меняется при
            # смене фамилии или почтового домена, тогда как адрес меняется
            # регулярно — а привязка принципала к внешней identity обязана
            # переживать такие изменения. Тот же атрибут читает и каталог
            # (GRANTOR_IDP_LDAP_SUBJECT_ATTRIBUTE), иначе вход и поллинг
            # адресовали бы человека по-разному.
            "sub_mode": "user_username",
        },
    )
    if code >= 300:
        sys.exit(f"authentik-bootstrap: create oidc provider: {provider}")
    call("POST", "/core/applications/", {"name": "Grantor", "slug": "grantor", "provider": provider["pk"]})


def main() -> None:
    wait_ready()
    groups = ensure_groups()
    ensure_users(groups)
    ensure_oidc(ensure_groups_scope())
    print("authentik-bootstrap: done")


if __name__ == "__main__":
    main()
