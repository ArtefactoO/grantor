# ADR-0032: Protect statistics membership and MongoDB bucket identity

## Decision

PostgreSQL pg_read_all_stats is a protected permission with explicit target, administration and role-OID checks. It does not become a normal account lifecycle object. MongoDB bucket resources are recognized by discovery so clusterMonitor can be observed correctly; desired policy does not convert them into ordinary collections.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
