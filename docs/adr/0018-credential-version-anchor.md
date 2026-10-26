# ADR-0018: Anchor the observed credential version

## Decision

Track a credential-version anchor so changes outside Grantor can be detected. Compare evidence against the intended Vault version and account lifecycle rather than assuming a stored reference remains current forever. External drift is a visible condition and must not automatically justify overwriting a target credential.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
