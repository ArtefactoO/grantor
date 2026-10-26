# ADR-0011: Expose security findings through audit and metrics

## Decision

Use the existing audit and Prometheus surfaces for security findings rather than introducing a separate findings system. Keep finding identity, severity and relevant operation/resource context without credentials or business payloads. Audit remains append-only and metrics must not expose sensitive or unbounded values.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
