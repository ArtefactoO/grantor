package connector

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrBadSignature возвращается, когда подпись не соответствует
	// каноничному представлению Job (порча задания или чужой ключ).
	ErrBadSignature = errors.New("connector: signature verification failed")
	// ErrUnsupportedVersion возвращается, когда ProtocolVersion задания не
	// совпадает с поддерживаемой (version negotiation, раздел 24).
	ErrUnsupportedVersion = errors.New("connector: unsupported protocol version")
	// ErrUnknownKey возвращается, когда verifier не знает KeyID из Envelope.
	ErrUnknownKey = errors.New("connector: unknown signing key")
)

// canonicalJob — фиксированная форма Job для подписи. Порядок и набор полей
// зафиксированы контрактом v1 и не зависят от wire-тегов Job: json.Marshal
// сериализует поля структуры в порядке объявления, поэтому байты стабильны
// между запусками и версиями Go. Поле Signature сюда не входит — оно живёт
// в Envelope, поэтому подпись Job от него не зависит.
//
// ВАЖНО: любое новое security-значимое поле Job должно быть добавлено сюда,
// иначе оно не будет покрыто подписью.
type canonicalJob struct {
	ID              string          `json:"id"`
	Kind            JobKind         `json:"kind"`
	ConnectionID    string          `json:"connection_id"`
	Engine          string          `json:"engine"`
	ProtocolVersion string          `json:"protocol_version"`
	IssuedAt        int64           `json:"issued_at"`
	Deadline        int64           `json:"deadline"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Nonce           string          `json:"nonce"`
	Payload         json.RawMessage `json:"payload"`
}

// CanonicalBytes возвращает детерминированное каноничное представление Job,
// над которым вычисляется подпись. Для одного и того же Job байты всегда
// одинаковы; изменение любого подписываемого поля меняет байты. Пустой
// Payload нормализуется к JSON null, чтобы nil и [] давали одинаковый
// результат; невалидный JSON в Payload приводит к ошибке.
func CanonicalBytes(job Job) ([]byte, error) {
	payload := job.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	// json.Marshal компактифицирует и валидирует RawMessage (снимает
	// незначащие пробелы), поэтому различия в форматировании Payload не
	// влияют на подпись.
	b, err := json.Marshal(canonicalJob{
		ID:              job.ID,
		Kind:            job.Kind,
		ConnectionID:    job.ConnectionID,
		Engine:          job.Engine,
		ProtocolVersion: job.ProtocolVersion,
		IssuedAt:        job.IssuedAt,
		Deadline:        job.Deadline,
		IdempotencyKey:  job.IdempotencyKey,
		Nonce:           job.Nonce,
		Payload:         payload,
	})
	if err != nil {
		return nil, fmt.Errorf("connector: canonicalize job: %w", err)
	}
	return b, nil
}

// Signer подписывает каноничные байты задания и сообщает KeyID, которым
// подпись можно проверить.
type Signer interface {
	Sign(data []byte) (sig []byte, keyID string, err error)
}

// Verifier проверяет подпись каноничных байтов задания против ключа KeyID.
// При несовпадении возвращает ErrBadSignature, при неизвестном KeyID —
// ErrUnknownKey.
type Verifier interface {
	Verify(keyID string, data, sig []byte) error
}

// SignJob каноникализирует Job и упаковывает его в подписанный Envelope.
func SignJob(s Signer, job Job) (Envelope, error) {
	data, err := CanonicalBytes(job)
	if err != nil {
		return Envelope{}, err
	}
	sig, keyID, err := s.Sign(data)
	if err != nil {
		return Envelope{}, fmt.Errorf("connector: sign job: %w", err)
	}
	return Envelope{Job: job, Signature: sig, KeyID: keyID}, nil
}

// VerifyEnvelope проверяет версию протокола и подпись задания. Сначала
// version negotiation (ErrUnsupportedVersion), затем повторная
// каноникализация Job и проверка подписи (ErrBadSignature/ErrUnknownKey).
func VerifyEnvelope(v Verifier, e Envelope) error {
	if e.Job.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: got %q, want %q",
			ErrUnsupportedVersion, e.Job.ProtocolVersion, ProtocolVersion)
	}
	data, err := CanonicalBytes(e.Job)
	if err != nil {
		return err
	}
	if err := v.Verify(e.KeyID, data, e.Signature); err != nil {
		return err
	}
	return nil
}

// Две реализации подписи сосуществуют намеренно:
//
//   - HMAC-SHA256 — dev/тестовая: симметричный общий секрет, без PKI. Проста
//     в поднятии локального стека и в юнит-тестах, но требует, чтобы секрет
//     знали обе стороны, поэтому в production не используется.
//   - Ed25519 — целевая для production: асимметричная. Приватный ключ не
//     покидает connector, gateway хранит только публичные ключи. Ложится на
//     ту же mTLS/PKI-инфраструктуру identity (раздел 24) и позволяет
//     верифицировать задания без общего секрета.
//
// Обе реализуют Signer/Verifier, поэтому выбор алгоритма — деталь конфигурации,
// а не кода operation engine.

// HMACSigner подписывает задания HMAC-SHA256 общим секретом (dev/тест).
type HMACSigner struct {
	keyID  string
	secret []byte
}

// NewHMACSigner создаёт HMAC-подписанта. Секрет копируется.
func NewHMACSigner(keyID string, secret []byte) *HMACSigner {
	dup := make([]byte, len(secret))
	copy(dup, secret)
	return &HMACSigner{keyID: keyID, secret: dup}
}

// Sign возвращает HMAC-SHA256 от data и свой KeyID.
func (s *HMACSigner) Sign(data []byte) ([]byte, string, error) {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write(data) // hash.Hash.Write не возвращает ошибок.
	return mac.Sum(nil), s.keyID, nil
}

// HMACVerifier проверяет HMAC-SHA256 подписи одним общим секретом (dev/тест).
type HMACVerifier struct {
	keyID  string
	secret []byte
}

// NewHMACVerifier создаёт HMAC-верификатор для keyID. Секрет копируется.
func NewHMACVerifier(keyID string, secret []byte) *HMACVerifier {
	dup := make([]byte, len(secret))
	copy(dup, secret)
	return &HMACVerifier{keyID: keyID, secret: dup}
}

// Verify пересчитывает HMAC и сравнивает его в постоянном времени.
func (v *HMACVerifier) Verify(keyID string, data, sig []byte) error {
	if keyID != v.keyID {
		return fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	mac := hmac.New(sha256.New, v.secret)
	_, _ = mac.Write(data) // hash.Hash.Write не возвращает ошибок.
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

// ED25519Signer подписывает задания Ed25519 приватным ключом (production).
type ED25519Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewED25519Signer создаёт Ed25519-подписанта поверх приватного ключа.
func NewED25519Signer(keyID string, priv ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{keyID: keyID, priv: priv}
}

// Sign возвращает Ed25519-подпись data и свой KeyID.
func (s *ED25519Signer) Sign(data []byte) ([]byte, string, error) {
	if len(s.priv) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("connector: invalid ed25519 private key size %d", len(s.priv))
	}
	return ed25519.Sign(s.priv, data), s.keyID, nil
}

// ED25519Verifier проверяет Ed25519-подписи публичным ключом (production).
type ED25519Verifier struct {
	keyID string
	pub   ed25519.PublicKey
}

// NewED25519Verifier создаёт Ed25519-верификатор поверх публичного ключа.
func NewED25519Verifier(keyID string, pub ed25519.PublicKey) *ED25519Verifier {
	return &ED25519Verifier{keyID: keyID, pub: pub}
}

// Verify проверяет Ed25519-подпись. Неизвестный keyID — ErrUnknownKey,
// несовпадение — ErrBadSignature.
func (v *ED25519Verifier) Verify(keyID string, data, sig []byte) error {
	if keyID != v.keyID {
		return fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
	}
	if len(v.pub) != ed25519.PublicKeySize {
		return fmt.Errorf("connector: invalid ed25519 public key size %d", len(v.pub))
	}
	if !ed25519.Verify(v.pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}
