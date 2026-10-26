# ADR-0022: Version PostgreSQL role-policy helpers

## Decision

A PostgreSQL role-policy template describes supported database/object grants and default privileges. Version the helper contract and check the expected target identity and administration authority before applying it. Create, adopt and repair remain explicit operations. Unsupported ownership or object scope must remain a blocking condition.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
