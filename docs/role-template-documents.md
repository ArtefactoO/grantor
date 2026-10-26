# Base roles and role-policy templates

Base READ and READ/WRITE roles provide a supported starting policy for a database. An advanced template describes the desired role policy separately from account membership.

PostgreSQL policies distinguish current object grants, default privileges, ownership and direct grants. MongoDB policies retain resource/action scope and custom-role identity. The policy editor does not convert these engines into one interchangeable permission model.

Preview the target and policy, then inspect operation and observed evidence after create, adopt or repair. Unknown objects, conflicting identity and insufficient administration authority must block mutation rather than be guessed. Existing unmanaged roles require an explicit decision.

Policy changes do not prove that an account credential authenticates or that network/HBA admits it. See [readiness](postgres-access-readiness.md), [ADR-0022](adr/0022-postgresql-role-policy-helper.md) and [ADR-0023](adr/0023-mongodb-custom-role-policies.md).
