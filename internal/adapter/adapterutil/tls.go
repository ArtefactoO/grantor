package adapterutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// DefaultDialTimeout ограничивает установку одного TCP-соединения к целевой
// системе. Значение общее для всех adapters; per-engine request/response
// таймауты остаются локальными.
const DefaultDialTimeout = 10 * time.Second

// DialContextFunc — общий transport hook adapters. Production worker
// подставляет netguard.GuardedDialer; connector и unit-тесты по умолчанию
// используют обычный net.Dialer.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// DialContext позволяет использовать функцию как interface dialer (MongoDB).
func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// DefaultDialContext открывает TCP-соединение с общим adapter timeout.
func DefaultDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: DefaultDialTimeout}).DialContext(ctx, network, address)
}

// TLSDialContext оборачивает уже защищённый TCP dial TLS-handshake. ServerName
// выводится из исходного hostname до того, как guarded dialer закрепит
// соединение за числовым IP.
func TLSDialContext(dial DialContextFunc, base *tls.Config) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		cfg := base.Clone()
		if cfg.ServerName == "" {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				_ = raw.Close()
				return nil, errors.New("invalid TLS endpoint address")
			}
			cfg.ServerName = host
		}
		conn := tls.Client(raw, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, errors.New("tls handshake failed")
		}
		return conn, nil
	}
}

// BuildTLSConfig строит tls.Config по режиму подключения. Пустой режим и
// "disabled" означают отсутствие TLS (nil, nil). Семантика режимов повторяет
// libpq: require шифрует без проверки сертификата (или как verify-ca при
// заданном CA), verify-ca проверяет цепочку без hostname, verify-full —
// цепочку и hostname.
//
// ServerName выставляется в host безусловно: в require/verify-ca он не влияет
// на проверку (InsecureSkipVerify), а драйверы всё равно подставили бы host из
// адреса; verify-full использует его как проверяемое имя. Kafka передаёт
// host="" — kgo сам подставляет ServerName для каждого брокера.
func BuildTLSConfig(t adapter.TLSConfig, host string) (*tls.Config, error) {
	if t.Mode == "" || t.Mode == "disabled" {
		return nil, nil
	}

	certs, err := ClientCertificates(t)
	if err != nil {
		return nil, err
	}
	roots, err := RootCAPool(t.CACertPEM)
	if err != nil {
		return nil, err
	}
	conf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: certs,
		ServerName:   host,
	}
	switch t.Mode {
	case "require":
		// Как в libpq: require с заданным CA ведёт себя как verify-ca,
		// без CA — шифрование без проверки сертификата.
		conf.InsecureSkipVerify = true
		if roots != nil {
			conf.VerifyPeerCertificate = VerifyServerChain(roots)
		}
	case "verify-ca":
		// Проверяется цепочка сертификатов, но не hostname: стандартную
		// проверку отключаем и выполняем свою по цепочке.
		conf.InsecureSkipVerify = true
		conf.VerifyPeerCertificate = VerifyServerChain(roots)
	case "verify-full":
		conf.RootCAs = roots
	default:
		return nil, fmt.Errorf("unsupported tls mode %q", t.Mode)
	}
	return conf, nil
}

// ClientCertificates загружает клиентский сертификат, если он задан.
func ClientCertificates(t adapter.TLSConfig) ([]tls.Certificate, error) {
	hasCert := len(t.ClientCertPEM) > 0
	hasKey := len(t.ClientKeyPEM) > 0
	if !hasCert && !hasKey {
		return nil, nil
	}
	if hasCert != hasKey {
		return nil, errors.New("client certificate and key must be provided together")
	}
	cert, err := tls.X509KeyPair(t.ClientCertPEM, t.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	return []tls.Certificate{cert}, nil
}

// RootCAPool строит pool корневых сертификатов из PEM; при пустом PEM
// возвращает nil, что означает системный pool.
func RootCAPool(caPEM []byte) (*x509.CertPool, error) {
	if len(caPEM) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA certificate PEM")
	}
	return pool, nil
}

// VerifyServerChain возвращает проверку цепочки сертификатов сервера без
// проверки hostname (семантика verify-ca). При roots == nil используется
// системный pool.
func VerifyServerChain(roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("server did not present a certificate")
		}
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			certs[i] = cert
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := certs[0].Verify(opts); err != nil {
			return fmt.Errorf("verify server certificate chain: %w", err)
		}
		return nil
	}
}

// NewHTTPTransport собирает http.Transport для adapters поверх HTTP API
// (clickhouse, rabbitmq): TLS-конфигурация, dial timeout и консервативные
// лимиты пула. Значения (MaxIdleConns, IdleConnTimeout, ExpectContinueTimeout)
// повторяют прежние per-engine транспорты дословно.
func NewHTTPTransport(tlsCfg *tls.Config, dialTimeout time.Duration) *http.Transport {
	return NewHTTPTransportWithDialer(tlsCfg, dialTimeout, nil)
}

// NewHTTPTransportWithDialer эквивалентен NewHTTPTransport, но позволяет
// worker привязать SSRF policy-check к каждому реальному dial.
func NewHTTPTransportWithDialer(tlsCfg *tls.Config, dialTimeout time.Duration, dial DialContextFunc) *http.Transport {
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	return &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           dial,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: time.Second,
	}
}
