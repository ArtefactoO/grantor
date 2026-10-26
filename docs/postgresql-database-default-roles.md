# PostgreSQL database creation and base roles

The database-creation workflow can provision a database with base READ and READ/WRITE roles. The operation keeps database creation, role policy and observed results together and supports explicit recovery after partial completion.

Choose the target connection and database identity, inspect the proposed owner/policy, then follow the resulting operation. Base role names do not by themselves prove effective access. The adapter must establish supported current-object grants and default privileges for future objects under the configured owner contract.

An already existing database or role is not silently adopted. Reconcile target identity and ownership, then use the supported adopt/repair path. Do not grant broad privileges merely to complete a failed workflow.

The administration identity follows the explicit SUPERUSER authority model. See [PostgreSQL operations](postgresql-access-operations.md), [role templates](role-template-documents.md) and [ADR-0025](adr/0025-database-default-role-workflow.md).
