# PostgreSQL roles, access and HBA

## Administration authority

Managed account/database creation and direct role-policy workflows use a dedicated Grantor administration identity under the accepted PostgreSQL SUPERUSER model. CREATEROLE alone does not establish equivalent authority. Restrict its endpoint, network admission and secret access. Do not reuse an application account.

## Role policy

Base READ and READ/WRITE policies are database-scoped and account for current objects and defaults for future objects under the supported owner contract. Direct object privileges remain distinct from role membership. Inspect the resulting grants and object identity rather than inferring access from a role name.

A managed database workflow creates the database and its base roles through one operation with resumable evidence. Existing databases and unmanaged roles require explicit adoption/repair decisions. See [database roles](postgresql-database-default-roles.md) and the relevant ADRs.

## Network and HBA

PostgreSQL sees the address at the database end of the connection. Through HAProxy, that may be a proxy address rather than the caller's address. For example, a client can use VIP `192.0.2.10`, while PostgreSQL observes proxies `192.0.2.11` and `192.0.2.12`. These are documentation addresses.

Admit only the intended user, database and actual source path. A parsed HBA rule is evidence of file content, not proof that PostgreSQL loaded it. A successful network connection or SCRAM negotiation is not proof that the password authenticated.

## Credential and grant verification

Confirm endpoint identity and the selected database. Prove the account password before enabling dependent CONNECT access. Check current LOGIN, membership, direct object privileges and supported READ/RW evidence. Keep grant readiness, credential proof, HBA evidence and inventory freshness separate.

`pg_read_all_stats` is a protected statistics membership with explicit authority and OID checks. It is not an ordinary account lifecycle object. Connector execution requires the matching statistics-membership capability.

Do not run business-data reads as a generic readiness probe. Use supported metadata and bounded checks. Review [readiness](postgres-access-readiness.md), [role templates](role-template-documents.md) and [ADR-0035](adr/0035-postgresql-direct-object-privileges.md).
