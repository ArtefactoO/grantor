# API clients and connection onboarding

The API accepts scoped machine service tokens and personal API keys. Personal keys remain bounded by the owner's role, scope and expiry. Browser sessions additionally require the configured CSRF header for mutations.

Use the included CLI to inspect the implemented commands and request format:

```sh
python3 scripts/grantor_api.py --help
```

The helper supports connection, account and access workflows. Keep tokens in its documented environment/file inputs, not command-line examples or shell history. Check identity and permissions before submitting a mutation.

## Registration

`/api/v1/connections` manages connection metadata. Register a target with its engine, environment, endpoints, discovery settings and approved credential source. A connection registration receipt distinguishes accepted input from confirmed readiness. Repeat an idempotent request with the same identity instead of creating a duplicate target.

Direct and connector execution have different network paths. A private target name is admitted only under the matching execution/network policy. Never relax validation just to make an endpoint pass onboarding.

## After a request

Read the resulting operation, receipt and saved inventory. A successful API submission does not prove target mutation, credential usability or network reachability. Retry transient failures under the operation contract and preserve uncertain results for explicit resolution.

For account proof, role policy and PostgreSQL readiness, use the dedicated guides. API contracts are defined by handlers, types and regression tests, including [ADR-0030](adr/0030-api-credentials-and-connection-registration.md).
