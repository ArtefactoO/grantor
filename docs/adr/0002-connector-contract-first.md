# ADR-0002: Define the connector contract independently of transport

## Decision

The control plane can execute through a connector for targets in an isolated segment. Define job admission, target scope, credentials, results and failure semantics as a contract. A connector must preserve the direct adapter guarantees rather than create a second authorization model.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
