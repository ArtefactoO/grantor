# ADR-0027: Prove PostgreSQL credentials and recover role creation

## Decision

After a supported role/account mutation, independently verify the credential and observed LOGIN state. Retain evidence for partial provisioning or recovery. Do not infer a successful login from CREATE/ALTER success, a saved password or a same-named role. Apply identity checks before resuming the operation.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
