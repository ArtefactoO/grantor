# Local smoke checks

Start the disposable development stack with `make up`. Inspect `docker compose ps`, API readiness at `http://localhost:58082/health/ready` and the UI at `http://localhost:58080`.

Sign in through the bundled Authentik using `admin` / `grantor`. Confirm that the operator and viewer roles have their own boundaries and the disabled `blocked` account cannot sign in. These accounts are for local development only.

Use `python3 scripts/grantor_api.py --help` for CLI commands and the smoke harness under `scripts/smoke/` for supported disposable workflows. Read the harness before running it. Never point it at a shared target.

A useful smoke path establishes connection identity, triggers discovery, inspects inventory, creates a disposable account where supported and checks the resulting operation and observed privileges. Clean up only the objects created for the run.

Run `make test-integration` when changing lifecycle, credential proof, cascades or connector behavior. Unit tests and UI screenshots do not replace target-level evidence.
