# ADR-0016: Restore an account as a new proven incarnation

## Decision

A tombstoned account is not reattached to an arbitrary same-named target account. Restoration creates a new lifecycle incarnation with the required credential proof and engine identity. Retain old history as historical evidence. A post-purge restore or identity conflict is rejected instead of silently reusing stale ownership.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
