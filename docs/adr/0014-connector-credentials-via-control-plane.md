# ADR-0014: Deliver connector credentials from the control plane

## Decision

The worker resolves credentials centrally from Vault. A separate TypeCredentials frame follows the signed job and is bound to its JobID and nonce. The connector receives no VaultRef or Vault token and does not contact Vault. Credential material stays in memory and is cleared after execution; job, result and durable dedup payloads exclude it.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
