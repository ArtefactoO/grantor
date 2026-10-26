# ADR-0034: Make Redis no-auth an explicit mode

## Decision

A Redis connection without credentials is an explicit inventory mode. Do not interpret authentication errors as permission to retry anonymously. No-auth discovery does not imply user, ACL or credential-management capabilities. Preserve the supported Redis version and mode contract.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
