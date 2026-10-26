# ADR-0035: Model PostgreSQL direct object privileges separately

## Decision

Direct grants on PostgreSQL objects remain distinct from inherited role membership. Preserve object identity, owner and supported privilege scope. Observe direct and effective access under the documented contract, while keeping insufficient or stale evidence separate from confirmed denial. Do not rewrite unrelated privileges during repair.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
