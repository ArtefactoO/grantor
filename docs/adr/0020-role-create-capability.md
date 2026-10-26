# ADR-0020: Declare role creation as a separate capability

## Decision

Creating a non-login role is an explicit role.create capability. It is different from account creation and role membership. Validate identity, administration authority, policy and duplicate/recovery behavior. An adapter that can list roles does not automatically support creating or repairing them.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
