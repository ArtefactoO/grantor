# ADR-0015: Separate metadata edits from locked reconfiguration

## Decision

Connection presentation edits and execution-sensitive reconfiguration have different contracts. Validate endpoint, engine and execution changes under the connection lock. Invalidate or reject incompatible stale work rather than letting old execution assumptions survive a reconfiguration. Keep the operation and audit evidence visible.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
