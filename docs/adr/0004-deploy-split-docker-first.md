# ADR-0004: Use Docker for development and portable image builds

## Decision

The repository owns component source, Dockerfiles and a development Compose stack. A shared deployment supplies its own orchestrator, TLS, secret delivery and external services. Kubernetes charts and Argo CD Applications are not bundled here. CI validates images without deploying an environment.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
