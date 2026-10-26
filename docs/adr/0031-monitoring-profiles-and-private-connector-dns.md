# ADR-0031: Separate monitoring profiles and private connector DNS

## Decision

Monitoring profiles describe least-privilege inventory/statistics access, including Redis and RabbitMQ-specific bundles. A monitoring role does not grant administrative capabilities. Private Kubernetes DNS can be admitted through a matching connector network guard, without broadly disabling endpoint validation. Preserve credential-source and persistence boundaries.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
