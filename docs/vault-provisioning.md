# Vault provisioning

Vault stores target administration credentials, managed account credentials and control-plane secret material. PostgreSQL metadata stores references and evidence, not password values.

Create the required mount and policies for your environment. Use separate API and worker policies with only the paths each process needs. For Kubernetes, configure Vault Kubernetes authentication and bind the intended service account and namespace. Static development tokens belong only to the local Compose stack.

The entrypoint environment variables define Vault address, auth method, role and mount/path settings. The Compose file provides a disposable development example. `deploy/vault/` contains credential-verification policy fragments, not a complete policy for every installation.

Versioned credential reads and verification are part of the account lifecycle. Keep the stored reference, target identity and credential-version anchor consistent. A rotation is complete only after the required target write and authentication proof succeed.

Connectors do not authenticate to Vault. The worker resolves credentials centrally and sends only the material for a specific admitted signed job. Keep connector CA private keys outside runtime Vault paths where possible and control signing-key access separately.

Back up Vault under your operational policy. Never place real credentials in example values, ConfigMaps, README commands or source history.
