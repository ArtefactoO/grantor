# ADR-0008: Use principals across engine-specific accounts

## Decision

A principal represents the logical owner of access. Accounts belong to specific target connections, while bindings express desired and observed permissions. Credentials retain their own ownership and management-consent boundaries. Cross-engine access must not erase engine-specific identity or imply that an observed account is managed.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
