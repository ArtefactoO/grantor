# ADR-0026: Use explicit SUPERUSER authority for PostgreSQL provisioning

## Decision

Managed PostgreSQL account creation and direct role-policy workflows use the accepted SUPERUSER authority model. CREATEROLE alone cannot establish the required guarantees. Verify the selected administration identity before mutation, preserve password proof and resumable evidence, and do not silently broaden a lesser account or reuse an application identity.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
