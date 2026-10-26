# ADR-0006: Execution connector protocol v1

## Decision

A connector opens an outbound mTLS session and authenticates with an admitted certificate identity. Verify signed jobs independently of transport trust. Bind results and credential frames to the correct job and nonce. Preserve scoped target admission, deadlines, safe failure semantics and duplicate handling. Durable protocol material excludes secret values.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
