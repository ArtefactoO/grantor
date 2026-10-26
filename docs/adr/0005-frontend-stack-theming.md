# ADR-0005: Use a typed React frontend and local UI workspace

## Decision

Use TypeScript and React with explicit routing and server-state handling. The repository-local UI workspace owns theme tokens, typography and reusable primitives. The application owns domain data and authorization. Preserve keyboard focus, light/dark support and reduced-motion behavior when adding transitions.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
