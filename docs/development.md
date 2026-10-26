# Development

Use Docker for Go checks, frontend checks and migrations. The Makefile defines the supported container images and persistent dependency caches.

```sh
make up
make logs
make test
make test-integration
make web-test
make web-build
make lint
make build
make down
```

Unit tests run with the Go race detector. Integration tests create ephemeral PostgreSQL/Vault and engine-specific resources through the harness. `TEST_ID` isolates concurrent harness runs. Do not point this harness at a shared target.

## Local ports and accounts

| Component | Host port |
| --- | --- |
| Web UI | 58080 |
| API | 58082 |
| Metadata PostgreSQL | 55432 |
| Target PostgreSQL | 55433 |
| Vault | 58200 |
| Authentik | 59000 |
| Yopass | 58090 |

The local Authentik bootstrap creates `admin`, `operator`, `viewer` and a disabled `blocked` user. The development password is `grantor`. The Authentik administrator is `akadmin` with the same development password. Use these accounts only in the disposable local stack.

Readiness is `/health/ready`, liveness `/health/live`, metrics `/metrics`. Process settings use `GRANTOR_*` variables documented beside the entrypoints. `GRANTOR_DISCOVERY_INTERVAL` controls periodic worker discovery; `0` disables it.

## Database migrations

Migrations are in `db/migrations`. `make migrate-up` and `make migrate-status` require `GRANTOR_DB_DSN`. They run in Docker, so a host database may need `host.docker.internal` rather than container-local `localhost`.

## UI

`web/packages/project-ui` is an included npm workspace. Application routes own authorization, API access and domain logic. Theme tokens and reusable components live in the package. Update tests for state, keyboard behavior and stale-data handling when changing a workflow.

Pull requests and pushes to `main` run Gitleaks and the lightweight CLI tests automatically. Go tests with the race detector, Go lint/build, UI tests/build and container builds run only through **Actions → CI → Run workflow**. This workflow has no deployment credential or registry push. The separate `make test-integration` harness remains an explicit local check.
