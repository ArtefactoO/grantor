// Package conntest содержит тестовые помощники для runtime execution connector:
// генерацию self-signed CA и mTLS-сертификатов gateway/connector и сборку
// готовых tls.Config. Используется только тестами (unit и integration) пакетов
// gateway/agent/connector; в production-сборки не подключается (как fake и
// adaptertest).
package conntest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

// TLSPair — согласованная пара mTLS-конфигураций gateway и connector под общим
// self-signed CA.
type TLSPair struct {
	// ServerTLS — конфиг gateway (серверный сертификат + верификация клиента).
	ServerTLS *tls.Config
	// ClientTLS — конфиг connector (клиентский сертификат + доверие CA).
	ClientTLS *tls.Config
	// CACertPEM — PEM сертификата CA (для сценариев, строящих конфиги вручную).
	CACertPEM []byte
	// ServerName — имя, под которым выпущен серверный сертификат.
	ServerName string
}

// GenTLS генерирует CA, серверный (gateway) и клиентский (connector)
// сертификаты и собирает mTLS-конфиги через wire-хелперы. serverName попадает
// в SAN серверного сертификата и в ServerName клиентского конфига.
func GenTLS(t *testing.T, serverName, connectorID string) TLSPair {
	t.Helper()

	caCert, caKey := genCA(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	serverCert := genLeaf(t, caCert, caKey, pkix.Name{CommonName: serverName},
		[]string{serverName}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	clientCert := genLeaf(t, caCert, caKey, pkix.Name{CommonName: connectorID}, nil, nil)

	pool, err := wire.CertPoolFromPEM(caPEM)
	if err != nil {
		t.Fatalf("conntest: build CA pool: %v", err)
	}
	serverTLS, err := wire.ServerTLSConfig(serverCert, pool)
	if err != nil {
		t.Fatalf("conntest: server tls config: %v", err)
	}
	clientTLS, err := wire.ClientTLSConfig(clientCert, pool, serverName)
	if err != nil {
		t.Fatalf("conntest: client tls config: %v", err)
	}
	return TLSPair{ServerTLS: serverTLS, ClientTLS: clientTLS, CACertPEM: caPEM, ServerName: serverName}
}

// genCA создаёт self-signed CA-сертификат и его Ed25519 ключ.
func genCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("conntest: generate ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "grantor-connector-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("conntest: create ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("conntest: parse ca cert: %v", err)
	}
	return cert, priv
}

// genLeaf выпускает leaf-сертификат, подписанный CA, и возвращает готовый
// tls.Certificate (сертификат + приватный ключ).
func genLeaf(t *testing.T, caCert *x509.Certificate, caKey ed25519.PrivateKey,
	subject pkix.Name, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("conntest: generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		t.Fatalf("conntest: create leaf cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  priv,
		Leaf:        mustParse(t, der),
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("conntest: parse leaf cert: %v", err)
	}
	return cert
}

// serial возвращает случайный serial number для сертификата.
func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("conntest: serial: %v", err)
	}
	return n
}
