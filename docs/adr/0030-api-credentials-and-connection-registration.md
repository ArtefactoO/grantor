# ADR-0030: Scope API credentials and connection registration

## Decision

Machine tokens and personal API keys are distinct from browser sessions. Personal keys remain bounded by owner role, scope and expiry. Connection onboarding uses an approved credential source and an idempotent registration receipt. Accepted registration is not confirmed connectivity, administration authority or effective target access.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
