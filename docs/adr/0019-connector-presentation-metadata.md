# ADR-0019: Keep connector presentation separate from identity

## Decision

A connector display name and environment improve navigation but are not authorization identity. Preserve certificate/protocol identity and admission independently. Metadata edits must not make one connector impersonate another segment or change an existing job target.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
