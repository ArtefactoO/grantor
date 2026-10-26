# Adapter security review

Review each mutating capability independently before enabling it. Passing discovery tests does not establish mutation safety.

## Scope and identity

- Declare exact resource, permission, account and engine identity semantics.
- Reject ambiguous identifiers and cross-connection references.
- Treat capability support and caller authorization as separate checks.
- Escape identifiers using the target driver's supported mechanism. Never construct privileged commands from unchecked names.

## Credentials and authority

- Resolve only the credential required for the admitted operation.
- Keep secrets out of durable jobs, receipts, inventory, audit, errors and fixtures.
- Verify the administration authority required by the capability.
- Prove a new account credential before granting access that depends on it.
- Preserve explicit no-auth and externally managed credential boundaries.

## Operations and lifecycle

- Define idempotency, serialization, retry and uncertain-result behavior.
- Confirm target account identity before mutation or deletion.
- Make partial creation and credential proof resumable without repeating an unsafe create.
- Protect account incarnation and credential-version boundaries.
- Keep read failure distinct from absence; never revoke or delete based on an unavailable snapshot.

## Evidence

Contract tests must cover allowed and rejected operations, malformed identifiers, insufficient authority, unavailable targets, retries, stale identity and secret redaction. Integration tests must use disposable infrastructure and verify the actual target result.

A connector-capable operation needs the same semantics over the signed protocol. Verify independent transport identity, job signature, nonce, credential binding and duplicate handling.
