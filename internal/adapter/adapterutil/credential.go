package adapterutil

import (
	"crypto/rand"
	"fmt"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const (
	// DefaultPasswordLength — длина генерируемого пароля, если политика не
	// задаёт свою.
	DefaultPasswordLength = 32
	// PasswordAlphabet — алфавит генерируемых паролей: только [a-zA-Z0-9]
	// для максимальной совместимости с клиентами и строками подключения.
	PasswordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию DefaultPasswordLength). Спецсимволы сознательно
// не используются для совместимости с клиентами и строками подключения.
// enginePrefix задаёт префикс движка в тексте ошибки ("<engine>: generate
// credential: ...").
func GenerateCredential(policy adapter.CredentialPolicy, enginePrefix string) (*adapter.Credential, error) {
	length := policy.Length
	if length <= 0 {
		length = DefaultPasswordLength
	}
	secret, err := RandomPassword(length)
	if err != nil {
		return nil, fmt.Errorf("%s: generate credential: %w", enginePrefix, err)
	}
	return &adapter.Credential{Kind: "password", Secret: secret}, nil
}

// HasPasswordSecret сообщает, содержит ли credential непустой секрет.
func HasPasswordSecret(c *adapter.Credential) bool {
	return c != nil && len(c.Secret) > 0
}

// RandomPassword строит пароль длиной n из PasswordAlphabet через crypto/rand.
// Rejection sampling исключает modulo bias.
func RandomPassword(n int) ([]byte, error) {
	out := make([]byte, 0, n)
	// limit — верхняя граница байтов с равномерным распределением по
	// алфавиту: 256 - 256 % len(PasswordAlphabet).
	limit := byte(256 - 256%len(PasswordAlphabet))
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("read random bytes: %w", err)
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, PasswordAlphabet[int(b)%len(PasswordAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return out, nil
}
