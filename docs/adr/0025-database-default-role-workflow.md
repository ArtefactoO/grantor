# ADR-0025: Provision a database with explicit base roles

## Decision

The database workflow can provision a PostgreSQL database and base READ/READ-WRITE roles together. Check identity, ownership, supported existing-object grants and future-object defaults. Keep partial work resumable and require explicit adopt/repair for conflicts. Role naming is not evidence that effective access is correct.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
