# Contributing

Open an issue for a reproducible bug or a proposed behavior change. Include the version, steps, expected result and a minimal sanitized example.

Create a branch from `main` and keep each pull request focused. Use a descriptive [Conventional Commit](https://www.conventionalcommits.org/) title. Explain the resulting behavior and any compatibility limit. Add a regression test when behavior changes.

Run the relevant checks before opening a pull request:

```sh
make test
make web-test
make web-build
make lint
```

Do not include credentials, real infrastructure inventories, runtime captures or generated audit reports. Use disposable fixtures and update the documentation when a configuration contract changes.

The UI package is included in `web/packages/project-ui`. It does not require a private registry.
