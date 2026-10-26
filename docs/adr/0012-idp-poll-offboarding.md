# ADR-0012: Detect offboarding through the identity provider

## Decision

Poll the configured identity provider for supported principal status changes. An unavailable or incomplete provider response is not evidence that all principals were deleted. Offboarding revokes managed access and enters the defined retention lifecycle. Purge and restore retain their own explicit identity and credential rules.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
