# ADR-0036: Report access readiness as independent evidence

## Decision

PostgreSQL readiness separates credential proof, grant observation, HBA evidence and inventory freshness. A cached rule does not prove loaded HBA state, and successful transport negotiation does not prove password authentication. Use bounded metadata checks, preserve unknown/unavailable outcomes and avoid business-row probes.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
