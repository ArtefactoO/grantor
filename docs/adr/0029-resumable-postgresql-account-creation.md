# ADR-0029: Resume account verification without repeating CREATE

## Decision

A partially created PostgreSQL account records creation and proof evidence. A retry can resume the appropriate verification step instead of creating a second account or blindly overwriting an existing identity. Recheck lifecycle and target identity, and preserve uncertain results for explicit resolution.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
