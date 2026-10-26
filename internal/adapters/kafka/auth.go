package kafka

import (
	"fmt"
	"strings"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/secret"
)

// Ключи per-connection auth-конфигурации в Attributes. Значения приходят из
// jsonb-колонки connections.discovery_config (см. internal/jobs/executor.go,
// discoveryConfigJSON) — так же, как postgres читает Attributes["database"].
const (
	attrSASLMechanism    = "sasl_mechanism"
	attrSecurityProtocol = "security_protocol"
)

// saslMechanism — механизм SASL-аутентификации admin credential.
type saslMechanism string

const (
	// mechNone — SASL не используется (например, mTLS или анонимный доступ).
	mechNone saslMechanism = "none"
	// mechPlain — SASL/PLAIN: логин и пароль в открытом виде внутри handshake.
	mechPlain saslMechanism = "plain"
	// mechScramSha256 — SASL/SCRAM-SHA-256.
	mechScramSha256 saslMechanism = "scram-sha-256"
	// mechScramSha512 — SASL/SCRAM-SHA-512.
	mechScramSha512 saslMechanism = "scram-sha-512"
)

// defaultMechanism — механизм по умолчанию для connection без явного
// sasl_mechanism. Сохраняет обратную совместимость: до появления
// per-connection auth adapter всегда ходил SASL/SCRAM-SHA-256, поэтому
// существующие подключения без атрибута продолжают работать без изменений.
const defaultMechanism = mechScramSha256

// securityProtocol — транспорт и способ аутентификации соединения, по смыслу
// повторяет Kafka client property security.protocol.
type securityProtocol string

const (
	// protoPlaintext — открытый транспорт без SASL.
	protoPlaintext securityProtocol = "plaintext"
	// protoSASLPlaintext — SASL поверх открытого транспорта.
	protoSASLPlaintext securityProtocol = "sasl_plaintext"
	// protoSASLSSL — SASL поверх TLS.
	protoSASLSSL securityProtocol = "sasl_ssl"
	// protoSSL — TLS без SASL (mTLS: аутентификация клиентским сертификатом).
	protoSSL securityProtocol = "ssl"
)

// authConfig — разобранная и проверенная на согласованность per-connection
// конфигурация аутентификации. Секретов не содержит: пароль живёт только в
// secret.Value и раскрывается при построении SASL-механизма.
type authConfig struct {
	mechanism saslMechanism
	protocol  securityProtocol
}

// parseAuthConfig разбирает per-connection auth-конфигурацию из Attributes и
// TLS-режима connection и проверяет её согласованность. Неуказанный механизм —
// scram-sha-256 (обратная совместимость), неуказанный protocol выводится из
// механизма и TLS-режима. Несогласованные комбинации (например sasl_ssl без
// TLS) отклоняются с понятной ошибкой.
func parseAuthConfig(cfg adapter.Connection) (authConfig, error) {
	mech, err := parseMechanism(adapterutil.StringAttr(cfg.Attributes, attrSASLMechanism))
	if err != nil {
		return authConfig{}, err
	}
	proto, explicit, err := parseProtocol(adapterutil.StringAttr(cfg.Attributes, attrSecurityProtocol))
	if err != nil {
		return authConfig{}, err
	}
	tlsOn := tlsEnabled(cfg.TLS)
	if !explicit {
		proto = inferProtocol(mech, tlsOn)
	}
	ac := authConfig{mechanism: mech, protocol: proto}
	if err := ac.validate(tlsOn); err != nil {
		return authConfig{}, err
	}
	return ac, nil
}

// parseMechanism нормализует sasl_mechanism. Пустое значение — механизм по
// умолчанию. GSSAPI и OAUTHBEARER вне области поддержки и отклоняются с явной
// ошибкой, а не молча трактуются как SCRAM.
func parseMechanism(raw string) (saslMechanism, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return defaultMechanism, nil
	case string(mechNone):
		return mechNone, nil
	case string(mechPlain):
		return mechPlain, nil
	case string(mechScramSha256):
		return mechScramSha256, nil
	case string(mechScramSha512):
		return mechScramSha512, nil
	case "gssapi", "oauthbearer":
		return "", fmt.Errorf("sasl mechanism %q is not supported (only none, plain, scram-sha-256, scram-sha-512)", raw)
	default:
		return "", fmt.Errorf("unknown sasl mechanism %q (want none, plain, scram-sha-256 or scram-sha-512)", raw)
	}
}

// parseProtocol нормализует security_protocol. Второй результат сообщает, был
// ли protocol задан явно: при пустом значении он выводится (inferProtocol).
func parseProtocol(raw string) (securityProtocol, bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", false, nil
	case string(protoPlaintext):
		return protoPlaintext, true, nil
	case string(protoSASLPlaintext):
		return protoSASLPlaintext, true, nil
	case string(protoSASLSSL):
		return protoSASLSSL, true, nil
	case string(protoSSL):
		return protoSSL, true, nil
	default:
		return "", false, fmt.Errorf("unknown security protocol %q (want plaintext, sasl_plaintext, sasl_ssl or ssl)", raw)
	}
}

// inferProtocol выводит security_protocol из механизма и TLS-режима, когда он
// не задан явно: SASL + TLS -> sasl_ssl, SASL без TLS -> sasl_plaintext,
// без SASL + TLS -> ssl, без SASL без TLS -> plaintext.
func inferProtocol(mech saslMechanism, tlsOn bool) securityProtocol {
	switch {
	case mech != mechNone && tlsOn:
		return protoSASLSSL
	case mech != mechNone && !tlsOn:
		return protoSASLPlaintext
	case mech == mechNone && tlsOn:
		return protoSSL
	default:
		return protoPlaintext
	}
}

// validate проверяет согласованность механизма, protocol и TLS-режима.
func (ac authConfig) validate(tlsOn bool) error {
	if ac.usesSASL() && ac.mechanism == mechNone {
		return fmt.Errorf("security protocol %q requires a SASL mechanism (set sasl_mechanism)", ac.protocol)
	}
	if !ac.usesSASL() && ac.mechanism != mechNone {
		return fmt.Errorf("security protocol %q cannot be combined with sasl mechanism %q (use sasl_plaintext or sasl_ssl)",
			ac.protocol, ac.mechanism)
	}
	if ac.usesTLS() && !tlsOn {
		return fmt.Errorf("security protocol %q requires tls mode != disabled", ac.protocol)
	}
	if !ac.usesTLS() && tlsOn {
		return fmt.Errorf("security protocol %q requires tls mode disabled (use sasl_ssl or ssl for encrypted transport)", ac.protocol)
	}
	return nil
}

// usesSASL сообщает, аутентифицируется ли соединение через SASL.
func (ac authConfig) usesSASL() bool {
	return ac.protocol == protoSASLPlaintext || ac.protocol == protoSASLSSL
}

// usesTLS сообщает, шифруется ли транспорт TLS.
func (ac authConfig) usesTLS() bool {
	return ac.protocol == protoSASLSSL || ac.protocol == protoSSL
}

// authenticatesClients сообщает, аутентифицирует ли кластер клиентов на этом
// подключении вообще.
//
// Ложь означает protocol=plaintext без SASL: соединение анонимно, любой, кто
// дотянулся до брокера, читает и пишет топики. Управление правами на таком
// кластере — фикция, поэтому признак уходит в topology и превращается в
// security finding подключения (см. adapterutil.AuthenticationKey).
//
// Проверять это через SECURITY_DISABLED нельзя: Redpanda не возвращает такой
// код никогда, и выключенная авторизация оставалась незаметной.
func (ac authConfig) authenticatesClients() bool {
	return ac.usesSASL() || ac.protocol == protoSSL
}

// managesScram сообщает, управляет ли adapter учётными данными через SCRAM API
// на этом подключении. Верно только для SCRAM-механизмов: на PLAIN/mTLS/none
// кластере грантор не создаёт и не ротирует SCRAM-пользователей (см.
// доменный doc-комментарий пакета, «Матрица механизмов»). От этого зависят и
// privilege gate ValidateConnection, и доступность account.create/delete и
// credential.rotate.
func (ac authConfig) managesScram() bool {
	return ac.mechanism == mechScramSha256 || ac.mechanism == mechScramSha512
}

// saslMechanism строит механизм franz-go для механизма подключения или
// (nil, false) для mechNone. Пароль раскрывается из secret.Value только здесь
// и уходит внутрь механизма, не попадая в тексты ошибок и логи.
func (ac authConfig) saslMechanism(username string, sec secret.Value) (sasl.Mechanism, bool) {
	switch ac.mechanism {
	case mechPlain:
		return plain.Auth{User: username, Pass: sec.RevealString()}.AsMechanism(), true
	case mechScramSha256:
		return scram.Auth{User: username, Pass: sec.RevealString()}.AsSha256Mechanism(), true
	case mechScramSha512:
		return scram.Auth{User: username, Pass: sec.RevealString()}.AsSha512Mechanism(), true
	default: // mechNone
		return nil, false
	}
}

// saslOpt строит kgo-опцию SASL для механизма или (nil, false) для mechNone.
func (ac authConfig) saslOpt(username string, sec secret.Value) (kgo.Opt, bool) {
	mech, ok := ac.saslMechanism(username, sec)
	if !ok {
		return nil, false
	}
	return kgo.SASL(mech), true
}

// tlsEnabled сообщает, включён ли TLS по режиму connection (пустой режим и
// "disabled" — без шифрования, как и в buildTLSConfig/newClient).
func tlsEnabled(t adapter.TLSConfig) bool {
	return t.Mode != "" && t.Mode != "disabled"
}
