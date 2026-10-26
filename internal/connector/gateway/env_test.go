package gateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

// writeEnvPEMs генерирует self-signed Ed25519 сертификат (сервер + роль CA),
// его приватный ключ и отдельный Ed25519 ключ подписи заданий, раскладывает
// их PEM-файлами во временный каталог и настраивает окружение
// GRANTOR_CONNECTOR_GATEWAY_* через t.Setenv.
func writeEnvPEMs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate cert key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gateway-env-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal cert key: %v", err)
	}

	_, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sign key: %v", err)
	}
	signDER, err := x509.MarshalPKCS8PrivateKey(signPriv)
	if err != nil {
		t.Fatalf("marshal sign key: %v", err)
	}

	write := func(name, blockType string, data []byte) string {
		path := filepath.Join(dir, name)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	certPath := write("tls.crt", "CERTIFICATE", der)
	t.Setenv("GRANTOR_CONNECTOR_GATEWAY_TLS_CERT", certPath)
	t.Setenv("GRANTOR_CONNECTOR_GATEWAY_TLS_KEY", write("tls.key", "PRIVATE KEY", keyDER))
	// Self-signed сертификат выступает и клиентским CA: для загрузки
	// конфигурации достаточно валидного PEM.
	t.Setenv("GRANTOR_CONNECTOR_GATEWAY_CLIENT_CA", certPath)
	t.Setenv("GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY", write("sign.key", "PRIVATE KEY", signDER))
	t.Setenv("GRANTOR_CONNECTOR_GATEWAY_KEY_ID", "env-test")
}

// TestNewServerFromEnv — общий env-загрузчик собирает рабочий Server из
// PEM-файлов, а отсутствие обязательной переменной — понятная ошибка (оба
// хоста gateway, standalone-бинарь и worker, используют этот путь).
func TestNewServerFromEnv(t *testing.T) {
	writeEnvPEMs(t)

	srv, err := gateway.NewServerFromEnv(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewServerFromEnv: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNewServerFromEnvMissingSignKey(t *testing.T) {
	writeEnvPEMs(t)
	t.Setenv("GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY", "")

	if _, err := gateway.NewServerFromEnv(nil, nil, nil); err == nil {
		t.Fatal("expected error without GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY")
	} else if !strings.Contains(err.Error(), "GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY") {
		t.Errorf("error %q does not name the missing variable", err)
	}
}
