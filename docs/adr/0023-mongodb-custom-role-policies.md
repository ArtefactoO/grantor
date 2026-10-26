# ADR-0023: Preserve MongoDB custom-role scope

## Decision

MongoDB role policies retain resource/action scope and custom-role identity. Validate supported resources and administration authority before mutation. Do not flatten engine-specific resource semantics into generic SQL-style roles. Discovery and desired policy remain separate observations.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
