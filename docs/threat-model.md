# Grantor threat model

## Assets and trust boundaries

Protect target credentials, connector signing keys, operator sessions, API tokens, target account identities, desired access, operation receipts and append-only audit.

The browser, API, worker, metadata database, Vault, identity provider, gateway, connector network and each target are separate trust boundaries. A capability manifest is not permission to cross a boundary.

## Required controls

| Risk | Implemented boundary |
| --- | --- |
| A viewer changes target access | Backend authorization on mutating endpoints; UI visibility is not an authorization check |
| A stolen browser request performs a mutation | Authenticated session and CSRF validation |
| Credentials leak through metadata or diagnostics | Explicit credential resolution, sanitized errors/results and secret-free durable payloads |
| A connector impersonates another segment | mTLS certificate identity and independent protocol checks |
| A gateway transport injects a job | Signed job verification, identity scope, nonce and credential-frame binding |
| Retries repeat a destructive operation | Per-connection serialization, idempotency and durable receipts |
| A failed read is interpreted as absence | Retryable/unavailable outcomes remain distinct from confirmed missing state |
| An adopted account silently becomes managed | Explicit credential-management consent and lifecycle state |
| A password write is mistaken for usable access | Credential proof and resumable provisioning evidence |
| A stale operation targets a replacement account | Engine identity and lifecycle/version anchors |

## Credentials

Vault is the credential source for the control plane. The connector receives only the credential required for an admitted job and does not receive a Vault token. Private keys and target credentials must not enter Git, ConfigMaps, screenshots or event payloads.

Use dedicated target administration identities with the authority required by the selected adapter. PostgreSQL managed creation and direct role-policy workflows have an explicit SUPERUSER authority model. Do not substitute a lesser account and claim equivalent guarantees. See [PostgreSQL operations](postgresql-access-operations.md).

## Operations and failure

Preserve uncertain and partial outcomes. Do not label an operation complete solely because it was submitted or a write call returned. Confirm target identity and the expected result. A timeout may require observation or an explicit resolution, rather than repeating a mutation blindly.

Approvals are a separate gate for configured dangerous operations. Audit must retain the requester, decision and resulting operation. Approval does not bypass target capability or credential checks.

Offboarding and purge are different transitions. Retention permits supported restoration before purge. A failed IdP poll is not evidence that every principal has been removed.

## Deployment responsibilities

The supplied Compose environment is disposable development infrastructure. A shared deployment needs HTTPS, a configured identity provider, scoped Vault policies, protected signing material, network boundaries, backups and operational monitoring.

Connector egress should be restricted to its gateway, DNS and admitted targets. Rotate certificates and signing material with the supplied PKI tools. Validate the actual certificate names, target endpoints and execution mode before enabling a connection.

## Review and reporting

Review a new adapter with the [security checklist](adapter-security-review.md), contract tests and integration tests against disposable targets. Security findings are recorded through audit and metrics. Report vulnerabilities using [SECURITY.md](../SECURITY.md).
