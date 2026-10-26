# Operator interface

The connection catalog supports search, filters, favorites and navigation context. Opening a saved connection reads inventory. Use its explicit refresh action when a new discovery is needed.

## Main workflows

A connection offers database creation, account creation and access assignment where its adapter supports them. Each action creates an operation whose result remains visible separately from the request.

Role selection shows issued roles first. Pending choices remain visible through search and refresh. PostgreSQL direct grants, role policies and HBA evidence retain their own scope and freshness.

The attention view groups operations that require a decision. Confirm the selected operation and its current state before approval or resolution. Bulk decisions preserve each child's result and do not convert partial success into total completion.

## Readiness and lifecycle

Credential proof, grants, HBA evidence and observed inventory establish different facts. Missing or stale evidence remains visible. A cached HBA snapshot does not prove that the server loaded that file or that a password can authenticate.

Removing a connection changes metadata and does not automatically drop target data. Account deletion, restoration, offboarding and purge have separate lifecycle rules. Read the [architecture](architecture.md) and [access-readiness guide](postgres-access-readiness.md) before destructive actions.

Themes, focus, dialogs and shared controls live in the local [UI workspace](../web/packages/project-ui/README.md).
