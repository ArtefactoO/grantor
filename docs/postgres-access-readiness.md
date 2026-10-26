# PostgreSQL access readiness

Readiness combines independent evidence. It must not infer a successful login from a grant, HBA entry, saved password or green UI state.

| Evidence | Establishes | Does not establish |
| --- | --- | --- |
| Target identity | The admitted endpoint/database identity | Correct credentials |
| Password proof | Authentication using the selected account credential | Every object privilege |
| Role/object grants | Supported observed privileges | Network or HBA admission |
| HBA snapshot | Parsed file rules at observation time | The loaded rules or password success |
| Inventory timestamp | Age of the saved discovery | Current target state |

Use the connection's access/readiness workflow and inspect each result and observation time. The API/CLI guide explains authentication and receipt handling. Refresh explicitly when fresh inventory is needed; reading the interface does not run discovery.

Password proof precedes dependent CONNECT changes. Partially created accounts retain operation evidence so verification can resume without an unsafe second CREATE. A restored account is a new credential-proven lifecycle incarnation.

Unknown, stale and unavailable checks remain distinct from denied and confirmed success. Readiness checks use supported metadata and must not become unrestricted business-data probes.
