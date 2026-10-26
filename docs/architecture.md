# Grantor architecture

Grantor is a database and broker inventory and access control plane. Its domain model distinguishes a person or service identity, an account on a particular connection, a resource, a permission and the binding between them.

## Components

- `cmd/api`: authenticated API, authorization and operation admission.
- `cmd/worker`: River jobs, discovery, reconciliation, mutations and optional connector gateway.
- `cmd/connector-gateway`: a standalone gateway when deployed separately.
- `cmd/connector`: outbound execution agent for an isolated network.
- `cmd/migrate`: versioned PostgreSQL migrations.
- `web`: React client and local UI workspace.

Metadata PostgreSQL stores desired state, observed inventory, jobs, operation receipts and audit. Vault stores credentials. Authentik/OIDC supplies operator identity. Yopass can deliver a credential through a controlled one-time handoff.

## Domain and state

A principal can own accounts on multiple connections. An account belongs to one target and has an engine-specific identity. A binding records intended and observed access separately. Capability declarations describe adapter support; they never grant authorization.

Discovery writes a saved inventory. Missing objects are reported as missing, while unmanaged permissions are not automatically revoked. A browser read uses this inventory and does not initiate target discovery. Manual and periodic refresh requests share deduplication.

Mutating work is serialized per connection and carries an idempotency key. Operations preserve intermediate, partial and uncertain outcomes. A transient Vault or target failure remains retryable and cannot become a confirmed success or a destructive cleanup decision.

## Execution paths

In direct mode, the worker resolves the required credential and calls the target adapter. In connector mode, the agent opens an outbound mTLS session to a gateway. The control plane sends a signed job and a separate credentials frame bound to its JobID and nonce. The connector verifies identity, signature and job binding before execution. Credential material remains in memory and is cleared after use. The connector has no Vault reference or Vault access.

Durable job deduplication and receipts protect retries. A connection reconfiguration invalidates relevant execution assumptions under the same locking contract. Presentation metadata does not replace connector identity.

## Credential and lifecycle boundaries

Passwords and their derivatives are excluded from metadata, job payloads, results, audit and errors. A successful write is not sufficient evidence that a credential can authenticate. Password proof is performed before access that depends on that credential is enabled.

Managed account creation records resumable provisioning evidence. Restore creates a new credential-proven incarnation, rather than attaching the old lifecycle to an arbitrary target account. Credential-version anchors detect changes made outside Grantor.

Account and connection deletion have distinct semantics. Removing a connection changes metadata and does not itself revoke or drop target objects. Offboarding revokes managed access, rotates controlled credentials and enters a retention period. Purge after that period is destructive. Accounts adopted without credential-management consent keep that boundary visible.

## Engine contracts

PostgreSQL supports direct and role-policy access, protected statistics membership and database provisioning under its explicit authority contract. MongoDB identity and custom roles preserve engine-specific scope, including bucket resources. Kafka uses per-connection SASL settings. Redis no-auth is an explicit connection mode and does not imply user-management capability.

See the [adapter review](adapter-security-review.md), [threat model](threat-model.md) and [ADRs](adr/) for individual decisions. Adapter source and regression tests define the implemented capability limits.
