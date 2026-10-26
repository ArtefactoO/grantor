# ADR-0010: Separate approval from execution

## Decision

Configured dangerous operations can require a confirmation decision before execution. Record requester, decision and operation identity. Approval does not bypass role checks, target capabilities, identity proof or credential policy. Preserve rejection, expiry, conflict and partial outcomes explicitly.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
