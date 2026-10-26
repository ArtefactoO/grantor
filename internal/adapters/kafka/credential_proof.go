package kafka

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kerr"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// ProveCredential verifies a Kafka SCRAM identity/password pair. Grantor can
// only prove credentials it manages through the SCRAM lifecycle; PLAIN, mTLS
// and unauthenticated connections are deliberately rejected.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	identity := account.EngineIdentity
	if identity == "" || len(credential.Secret) == 0 {
		return errors.New("kafka: prove credential: account identity and password are required")
	}
	auth, err := parseAuthConfig(cfg)
	if err != nil {
		return fmt.Errorf("kafka: prove credential for user %q: invalid auth configuration: %w", identity, err)
	}
	if !auth.managesScram() {
		return fmt.Errorf("kafka: prove credential for user %q: SCRAM lifecycle is required: %w",
			identity, adapter.ErrCredentialProofUnsupported)
	}

	err = a.probeCredential(ctx, cfg, identity, credential.Secret)
	if err != nil {
		if isAuthenticationFailure(err) {
			return fmt.Errorf("kafka: prove credential for user %q: %w", identity, adapter.ErrExternalIdentityConflict)
		}
		return fmt.Errorf("kafka: prove credential for user %q: target unavailable", identity)
	}

	wrong, err := randomCredentialProbePassword()
	if err != nil {
		return fmt.Errorf("kafka: prove credential for user %q: generate negative probe: %w", identity, err)
	}
	defer clear(wrong)
	negativeErr := a.probeCredential(ctx, cfg, identity, wrong)
	if negativeErr == nil {
		return fmt.Errorf("kafka: prove credential for user %q: target accepts an unrelated password: %w",
			identity, adapter.ErrCredentialProofUnsupported)
	}
	if !isAuthenticationFailure(negativeErr) {
		return fmt.Errorf("kafka: prove credential for user %q: negative probe is ambiguous: %w",
			identity, adapter.ErrCredentialProofUnsupported)
	}
	return nil
}

func (a *Adapter) probeCredential(ctx context.Context, cfg adapter.Connection, identity string, password []byte) error {
	probe := cfg
	probe.AdminCredential = adapter.Credential{
		Kind:     "password",
		Username: identity,
		Secret:   password,
	}
	client, err := a.newClient(probe)
	if err != nil {
		return err
	}
	defer client.close()
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err = client.adm.BrokerMetadata(reqCtx)
	return err
}

func isAuthenticationFailure(err error) bool {
	return errors.Is(err, kerr.SaslAuthenticationFailed)
}

func randomCredentialProbePassword() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	return encoded, nil
}
