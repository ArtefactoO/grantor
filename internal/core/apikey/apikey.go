// Package apikey stores personal API keys and independently verified UI owners.
// Key plaintext is returned once; only its SHA-256 hash reaches the database.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/auth"
)

const TokenPrefix = "grk_"
const MaximumLifetime = 90 * 24 * time.Hour

var (
	ErrNotFound         = errors.New("apikey: not found")
	ErrInvalidToken     = errors.New("apikey: invalid token")
	ErrInvalidParams    = errors.New("apikey: invalid parameters")
	ErrOwnerUnavailable = errors.New("apikey: owner authorization unavailable")
)

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func HasTokenPrefix(token string) bool { return strings.HasPrefix(token, TokenPrefix) }

func EffectiveRole(owner, ceiling auth.Role) auth.Role {
	if owner.Allows(ceiling) {
		return ceiling
	}
	if ceiling.Allows(owner) {
		return owner
	}
	return ""
}
