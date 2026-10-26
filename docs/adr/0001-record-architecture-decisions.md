# ADR-0001: Record architecture decisions

## Decision

Keep significant architectural contracts in versioned ADRs alongside code. Each decision states its context, chosen behavior and consequences. Implementation and tests remain the source for the shipped behavior. Update a decision when a trust, identity or lifecycle boundary changes.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
