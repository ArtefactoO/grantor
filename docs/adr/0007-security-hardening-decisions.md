# ADR-0007: Keep independent security checks

## Decision

Do not collapse transport identity, job signature, target admission and operation authorization into one check. Browser mutations require session/CSRF controls. Use bounded operations and sanitized failures. Validate the actual target result and keep uncertain execution distinct from confirmed completion.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
