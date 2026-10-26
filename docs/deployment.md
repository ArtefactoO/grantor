# Deployment

Build the application and web images from this repository:

```sh
docker build -t grantor-app:local .
docker build -f Dockerfile.web -t grantor-web:local .
```

The application image includes API, worker, connector, connector-gateway and migration binaries. Select the component through its entrypoint. The Compose file demonstrates component commands and dependencies.

A shared environment needs PostgreSQL 15+, Vault, an identity provider and, when used, Yopass. Provide `GRANTOR_*` settings from the entrypoint contracts. Run migrations before starting a version that depends on them. Route the web application's API/auth requests to the API service through the supplied nginx configuration.

Use your own image registry, TLS names, secret delivery and orchestration. A Kubernetes chart or Argo CD Application is not bundled in this repository. GitHub Actions builds images only when **Actions → CI → Run workflow** is started manually. It does not publish or deploy them.

For isolated targets, read [connector deployment](connector-deployment.md). Prepare [Vault policies](vault-provisioning.md) and review the [threat model](threat-model.md) before exposing the service.
