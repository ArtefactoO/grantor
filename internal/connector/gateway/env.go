package gateway

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

// Общая загрузка конфигурации gateway из окружения. Используется двумя
// хостами одного и того же runtime (ADR-0002): standalone-бинарём
// cmd/connector-gateway и worker-процессом, встраивающим gateway с этапа 2
// (routing операций по connections.execution_mode). Логика не дублируется:
// оба читают одни и те же GRANTOR_CONNECTOR_GATEWAY_* переменные.
//
// Переменные окружения:
//
//   - GRANTOR_CONNECTOR_GATEWAY_TLS_CERT / _TLS_KEY — пути к PEM серверного
//     сертификата и приватного ключа gateway. Обязательны.
//   - GRANTOR_CONNECTOR_GATEWAY_CLIENT_CA — путь к PEM CA, которым подписаны
//     клиентские сертификаты connector (mTLS identity). Обязателен.
//   - GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY — путь к PEM Ed25519 приватного
//     ключа (PKCS#8), которым gateway подписывает задания. Обязателен.
//   - GRANTOR_CONNECTOR_GATEWAY_KEY_ID — идентификатор ключа подписи (KeyID
//     в Envelope), по умолчанию "gateway".
//   - GRANTOR_CONNECTOR_GATEWAY_MAX_INFLIGHT — предел одновременных in-flight
//     заданий на connector (этап 3); пусто/0 — дефолт пакета (8).

// defaultSignKeyID — KeyID подписи заданий по умолчанию.
const defaultSignKeyID = "gateway"

// NewServerFromEnv собирает Server из переменных окружения
// GRANTOR_CONNECTOR_GATEWAY_* (см. doc-комментарий выше). Dedup опционален:
// nil оставляет in-memory store (standalone без metadata DB); worker передаёт
// durable store поверх connector_job_dedup.
func NewServerFromEnv(logger *slog.Logger, dedup DedupStore, observer SessionObserver) (*Server, error) {
	tlsCfg, err := serverTLSFromEnv()
	if err != nil {
		return nil, err
	}
	signer, err := signerFromEnv()
	if err != nil {
		return nil, err
	}
	maxInFlight, err := maxInFlightFromEnv()
	if err != nil {
		return nil, err
	}
	return New(Config{
		TLS:             tlsCfg,
		Signer:          signer,
		Logger:          logger,
		Dedup:           dedup,
		MaxInFlight:     maxInFlight,
		SessionObserver: observer,
	})
}

// maxInFlightFromEnv читает необязательный предел in-flight заданий; пустая
// переменная — 0 (дефолт пакета), отрицательное или нечисловое значение —
// ошибка старта.
func maxInFlightFromEnv() (int, error) {
	raw := os.Getenv("GRANTOR_CONNECTOR_GATEWAY_MAX_INFLIGHT")
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("gateway: parse GRANTOR_CONNECTOR_GATEWAY_MAX_INFLIGHT %q: %w", raw, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("gateway: GRANTOR_CONNECTOR_GATEWAY_MAX_INFLIGHT must be >= 0, got %d", n)
	}
	return n, nil
}

// serverTLSFromEnv строит серверный tls.Config gateway из PEM-файлов,
// заданных окружением (сертификат, ключ, клиентский CA).
func serverTLSFromEnv() (*tls.Config, error) {
	certPEM, err := readRequiredFile("GRANTOR_CONNECTOR_GATEWAY_TLS_CERT")
	if err != nil {
		return nil, err
	}
	keyPEM, err := readRequiredFile("GRANTOR_CONNECTOR_GATEWAY_TLS_KEY")
	if err != nil {
		return nil, err
	}
	caPEM, err := readRequiredFile("GRANTOR_CONNECTOR_GATEWAY_CLIENT_CA")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: load server certificate: %w", err)
	}
	clientCAs, err := wire.CertPoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: load client CA: %w", err)
	}
	return wire.ServerTLSConfig(cert, clientCAs)
}

// signerFromEnv собирает Ed25519-подписанта заданий из PEM приватного ключа,
// путь к которому задан окружением.
func signerFromEnv() (connector.Signer, error) {
	keyPEM, err := readRequiredFile("GRANTOR_CONNECTOR_GATEWAY_SIGN_KEY")
	if err != nil {
		return nil, err
	}
	priv, err := parseEd25519PrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: load signing key: %w", err)
	}
	keyID := os.Getenv("GRANTOR_CONNECTOR_GATEWAY_KEY_ID")
	if keyID == "" {
		keyID = defaultSignKeyID
	}
	return connector.NewED25519Signer(keyID, priv), nil
}

// parseEd25519PrivateKey разбирает PEM-блок PKCS#8 с Ed25519 приватным ключом.
func parseEd25519PrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519.PrivateKey", key)
	}
	return priv, nil
}

// readRequiredFile читает файл, путь к которому задан переменной env; пустая
// переменная или ошибка чтения — ошибка старта.
func readRequiredFile(env string) ([]byte, error) {
	path := os.Getenv(env)
	if path == "" {
		return nil, fmt.Errorf("gateway: %s is required", env)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway: read %s (%s): %w", env, path, err)
	}
	return data, nil
}
