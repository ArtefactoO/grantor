# ADR-0033: Declare connector statistics-membership support

## Decision

PostgreSQL statistics membership can run over a connector only with the postgres.stats_membership.v1 capability. Preserve the direct path checks for target identity, administration authority and protected-role OIDs. An older connector must reject unsupported work rather than claim successful execution.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
