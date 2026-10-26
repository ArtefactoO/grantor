# ADR-0028: Prove the password before dependent CONNECT access

## Decision

When a workflow depends on a new account credential, prove authentication before enabling dependent CONNECT access. Keep proof scoped to the intended target and account incarnation. Authentication failure remains a failed or resumable operation and must not be masked by successful grant metadata.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
