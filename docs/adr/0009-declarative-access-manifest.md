# ADR-0009: Admit declarative access as explicit operations

## Decision

A declarative access request is validated and planned against supported identities and capabilities. Bulk work keeps per-child outcomes, idempotency and audit. Do not turn missing or failed observations into implicit revocation. A submitted manifest is desired intent, not proof of effective access.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
