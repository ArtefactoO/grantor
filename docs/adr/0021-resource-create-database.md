# ADR-0021: Declare database creation explicitly

## Decision

Database creation is an explicit resource.create.database capability. Validate database identity, owner and supported engine authority. Preserve resumable results if later policy steps fail. Do not silently adopt an existing database or grant broad ownership to force completion.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
