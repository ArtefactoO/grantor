package connector_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ArtefactoO/grantor/internal/connector"
)

// signerPair связывает Signer с совместимым Verifier для табличных тестов.
type signerPair struct {
	name     string
	signer   connector.Signer
	verifier connector.Verifier
}

// newED25519 генерирует Ed25519 signer/verifier с заданным keyID.
func newED25519(t *testing.T, keyID string) (*connector.ED25519Signer, *connector.ED25519Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return connector.NewED25519Signer(keyID, priv), connector.NewED25519Verifier(keyID, pub)
}

// pairs возвращает обе реализации подписи для общих тестов sign/verify.
func pairs(t *testing.T) []signerPair {
	t.Helper()
	edSigner, edVerifier := newED25519(t, "ed-1")
	secret := []byte("dev-shared-secret")
	return []signerPair{
		{
			name:     "hmac",
			signer:   connector.NewHMACSigner("hmac-1", secret),
			verifier: connector.NewHMACVerifier("hmac-1", secret),
		},
		{
			name:     "ed25519",
			signer:   edSigner,
			verifier: edVerifier,
		},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, p := range pairs(t) {
		t.Run(p.name, func(t *testing.T) {
			env, err := connector.SignJob(p.signer, sampleJob())
			if err != nil {
				t.Fatalf("SignJob: %v", err)
			}
			if len(env.Signature) == 0 {
				t.Fatal("SignJob produced empty signature")
			}
			if err := connector.VerifyEnvelope(p.verifier, env); err != nil {
				t.Errorf("VerifyEnvelope: %v", err)
			}
		})
	}
}

func TestVerifyTamperedJob(t *testing.T) {
	for _, p := range pairs(t) {
		t.Run(p.name, func(t *testing.T) {
			env, err := connector.SignJob(p.signer, sampleJob())
			if err != nil {
				t.Fatalf("SignJob: %v", err)
			}
			// Порча задания после подписи: подпись больше не соответствует
			// каноничным байтам.
			env.Job.Engine = "mongodb"
			if err := connector.VerifyEnvelope(p.verifier, env); !errors.Is(err, connector.ErrBadSignature) {
				t.Errorf("VerifyEnvelope after tamper = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	for _, p := range pairs(t) {
		t.Run(p.name, func(t *testing.T) {
			env, err := connector.SignJob(p.signer, sampleJob())
			if err != nil {
				t.Fatalf("SignJob: %v", err)
			}
			env.Signature[0] ^= 0xFF
			if err := connector.VerifyEnvelope(p.verifier, env); !errors.Is(err, connector.ErrBadSignature) {
				t.Errorf("VerifyEnvelope after signature tamper = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	env, err := connector.SignJob(connector.NewHMACSigner("hmac-1", []byte("s")), sampleJob())
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	verifier := connector.NewHMACVerifier("hmac-2", []byte("s"))
	if err := connector.VerifyEnvelope(verifier, env); !errors.Is(err, connector.ErrUnknownKey) {
		t.Errorf("VerifyEnvelope with unknown key = %v, want ErrUnknownKey", err)
	}
}

func TestVerifyForeignKey(t *testing.T) {
	t.Run("hmac", func(t *testing.T) {
		env, err := connector.SignJob(connector.NewHMACSigner("hmac-1", []byte("secret-a")), sampleJob())
		if err != nil {
			t.Fatalf("SignJob: %v", err)
		}
		// Тот же keyID, но другой секрет: чужой ключ.
		verifier := connector.NewHMACVerifier("hmac-1", []byte("secret-b"))
		if err := connector.VerifyEnvelope(verifier, env); !errors.Is(err, connector.ErrBadSignature) {
			t.Errorf("VerifyEnvelope with foreign HMAC key = %v, want ErrBadSignature", err)
		}
	})

	t.Run("ed25519", func(t *testing.T) {
		signer, _ := newED25519(t, "ed-1")
		// Публичный ключ другой пары под тем же keyID: чужой ключ.
		foreignPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		env, err := connector.SignJob(signer, sampleJob())
		if err != nil {
			t.Fatalf("SignJob: %v", err)
		}
		verifier := connector.NewED25519Verifier("ed-1", foreignPub)
		if err := connector.VerifyEnvelope(verifier, env); !errors.Is(err, connector.ErrBadSignature) {
			t.Errorf("VerifyEnvelope with foreign ed25519 key = %v, want ErrBadSignature", err)
		}
	})
}

func TestVerifyUnsupportedVersion(t *testing.T) {
	secret := []byte("s")
	job := sampleJob()
	job.ProtocolVersion = "v2"
	// Подпись валидна, но version negotiation отклоняет задание раньше
	// проверки подписи.
	env, err := connector.SignJob(connector.NewHMACSigner("hmac-1", secret), job)
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	verifier := connector.NewHMACVerifier("hmac-1", secret)
	if err := connector.VerifyEnvelope(verifier, env); !errors.Is(err, connector.ErrUnsupportedVersion) {
		t.Errorf("VerifyEnvelope with wrong version = %v, want ErrUnsupportedVersion", err)
	}
}

// TestSignatureIndependentOfSignatureField: подпись считается над Job, а не
// над Envelope, поэтому изменение поля Envelope.Signature не влияет на
// каноничные байты самого Job.
func TestSignatureIndependentOfSignatureField(t *testing.T) {
	env, err := connector.SignJob(connector.NewHMACSigner("hmac-1", []byte("s")), sampleJob())
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}

	before, err := connector.CanonicalBytes(env.Job)
	if err != nil {
		t.Fatalf("CanonicalBytes(before): %v", err)
	}
	env.Signature = append(env.Signature, 0x00, 0x01, 0x02)
	after, err := connector.CanonicalBytes(env.Job)
	if err != nil {
		t.Fatalf("CanonicalBytes(after): %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("Envelope.Signature must not affect Job canonical bytes")
	}
}
