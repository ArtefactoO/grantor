# ADR-0013: Choose Kafka SASL per connection

## Decision

Kafka authentication settings belong to the connection and target contract. Support only the implemented mechanisms and do not silently substitute another one after a failure. A PLAIN-authenticated connection without an ACL authorizer can provide inventory under an existing identity, but does not imply account/ACL mutation support.

## Verification

The implementation and regression tests define the shipped behavior. Changes to identity, credentials, authorization or operation lifecycle must update the contract and the corresponding negative tests together. See the [architecture](../architecture.md) and [threat model](../threat-model.md).
