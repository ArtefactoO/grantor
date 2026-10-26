package wire

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

// minTLSVersion — минимальная версия TLS для транспорта connector. mTLS —
// обязательная часть модели доверия (раздел 4.3), устаревшие версии не
// допускаются.
const minTLSVersion = tls.VersionTLS12

// ServerTLSConfig строит tls.Config для gateway: серверный сертификат и
// обязательная верификация клиентского сертификата connector против clientCAs
// (mTLS identity, раздел 24). RequireAndVerifyClientCert гарантирует, что
// анонимные и неаутентифицированные connector отклоняются на TLS-уровне до
// любого обмена заданиями.
func ServerTLSConfig(cert tls.Certificate, clientCAs *x509.CertPool) (*tls.Config, error) {
	if clientCAs == nil {
		return nil, errors.New("wire: server tls config requires a client CA pool")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   minTLSVersion,
	}, nil
}

// ClientTLSConfig строит tls.Config для connector: клиентский сертификат как
// идентичность и roots для проверки сертификата gateway. serverName должен
// совпадать с SAN сертификата gateway.
func ClientTLSConfig(cert tls.Certificate, roots *x509.CertPool, serverName string) (*tls.Config, error) {
	if roots == nil {
		return nil, errors.New("wire: client tls config requires a root CA pool")
	}
	if serverName == "" {
		return nil, errors.New("wire: client tls config requires a server name")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   serverName,
		MinVersion:   minTLSVersion,
	}, nil
}

// CertPoolFromPEM собирает пул доверенных сертификатов из PEM-бандла.
func CertPoolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("wire: no certificates found in PEM bundle")
	}
	return pool, nil
}

// PeerCommonName возвращает CN клиентского сертификата из состояния TLS —
// идентичность connector для логов и аудита. Пустая строка, если пир не
// предъявил сертификат (при RequireAndVerifyClientCert такого не бывает).
func PeerCommonName(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// PeerCertificateNotAfter возвращает срок действия клиентского сертификата.
// Нулевое время — сертификата нет; это единственный источник, по которому
// control plane может предупредить об истечении до того, как связь
// оборвётся.
func PeerCertificateNotAfter(state tls.ConnectionState) time.Time {
	if len(state.PeerCertificates) == 0 {
		return time.Time{}
	}
	return state.PeerCertificates[0].NotAfter
}
