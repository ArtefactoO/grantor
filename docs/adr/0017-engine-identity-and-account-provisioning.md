# ADR-0017: Preserve engine identity and provisioning state

## Decision

An account name is insufficient identity across all engines. Store and compare the supported engine identity, connection and lifecycle incarnation. Account creation has a provisioning state and receipts for partial results. Do not mark access ready until the required credential proof and observations complete.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
