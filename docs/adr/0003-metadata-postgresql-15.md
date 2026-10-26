# ADR-0003: Use PostgreSQL 15+ for metadata

## Decision

PostgreSQL stores domain metadata, operation state, durable jobs and audit. Version schema changes through goose migrations. Target credentials are not metadata. Runtime components must use a compatible migrated schema, and migration failures must remain explicit.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
