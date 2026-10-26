# ADR-0026: Prove the current account password through a connector

## Decision

A connector password-proof operation authenticates with the selected current account credential under the signed execution contract. It checks target and account identity, excludes secret material from results and does not infer proof from a successful credential write. Unsupported connector capabilities block the operation.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
