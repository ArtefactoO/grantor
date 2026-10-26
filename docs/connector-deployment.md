# Deploy an execution connector

A connector reaches targets in a network that the control plane cannot access directly. It opens an outbound mTLS session to a gateway. It does not listen for inbound jobs and has no Vault access.

## Prepare identity and signing material

```sh
scripts/connector-pki.sh \
  --out-dir ./pki \
  --gateway-san dns:gateway.example.com \
  --connector-id segment-a
```

The tool generates a connector CA, gateway certificate, connector client certificate and Ed25519 signing/verification keys. Keep the CA private key offline and signing material only on the gateway. Store runtime private material in your secret manager. The generated directory must not be committed.

The gateway SAN must match the name used by the connector. The connector certificate identity must match its admitted connector ID. Transport identity and signed job validation are independent checks.

## Gateway

The worker can host a gateway or you can run `cmd/connector-gateway` separately. Configure the required `GRANTOR_CONNECTOR_GATEWAY_*` TLS and signing files documented in those entrypoints. Restrict network access and expose only the intended listener.

## Connector

Build the binary with `make bins`. Its required file-based settings include:

| Variable | Meaning |
| --- | --- |
| `GRANTOR_CONNECTOR_ID` | Admitted connector identity |
| `GRANTOR_CONNECTOR_GATEWAY_ADDR` | Gateway host and port |
| `GRANTOR_CONNECTOR_GATEWAY_SERVER_NAME` | Expected gateway certificate name |
| `GRANTOR_CONNECTOR_TLS_CERT` | Client certificate file |
| `GRANTOR_CONNECTOR_TLS_KEY` | Client private-key file |
| `GRANTOR_CONNECTOR_CA` | Trusted gateway CA file |
| `GRANTOR_CONNECTOR_VERIFY_KEY` | Ed25519 verification-key file |

Mount files read-only and run the connector with a restricted identity. Allow egress only to the gateway, DNS and admitted targets. Kubernetes manifests and Helm charts are deployment-specific and are not included here.

The control plane sends target credentials in a separate frame bound to a signed job's ID and nonce. The connector keeps the material in memory and clears it after use. Durable payloads and results exclude credentials.

## Rotation and verification

Use `scripts/connector-cert-rotate.sh --help` for the rotation workflow. Verify certificate identity, gateway trust, signature key ID and successful admitted discovery after rotation. A connected transport alone does not prove a target operation.
