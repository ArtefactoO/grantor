# ADR-0024: Treat administration-credential changes as lifecycle operations

## Decision

Switching or rotating a connection administration credential needs admission, target proof, operation state and recovery evidence. A secret-manager write alone does not prove the credential works. Preserve the previous confirmed state until the supported verification and transition complete. Never expose credential material through receipts or audit.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
