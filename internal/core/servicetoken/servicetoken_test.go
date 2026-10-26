package servicetoken

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateTokenFormat(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("token %q does not start with %q", token, TokenPrefix)
	}
	body := strings.TrimPrefix(token, TokenPrefix)
	// Случайная часть — валидный base64url без паддинга нужной длины.
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("token body %q is not base64url: %v", body, err)
	}
	if len(raw) != tokenRandomBytes {
		t.Fatalf("decoded random bytes = %d, want %d", len(raw), tokenRandomBytes)
	}
	// Итоговая длина в районе 40 (спецификация): префикс + 40 символов base64.
	if got := len(token); got < 40 || got > 48 {
		t.Errorf("token length = %d, want ~44", got)
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	seen := make(map[string]bool, 128)
	for range 128 {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if seen[token] {
			t.Fatalf("GenerateToken produced a duplicate: %q", token)
		}
		seen[token] = true
	}
}

func TestHashToken(t *testing.T) {
	token := "grt_example-token-value"
	h := HashToken(token)
	// sha256-хекс: 64 символа, детерминирован, не содержит самого токена.
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64", len(h))
	}
	if h != HashToken(token) {
		t.Error("HashToken is not deterministic")
	}
	if strings.Contains(h, token) {
		t.Error("hash leaks the plaintext token")
	}
	if HashToken("grt_other") == h {
		t.Error("different tokens hashed to the same value")
	}
}

func TestHasTokenPrefix(t *testing.T) {
	if !HasTokenPrefix("grt_abc") {
		t.Error("HasTokenPrefix(grt_abc) = false, want true")
	}
	for _, s := range []string{"", "abc", "GRT_abc", "bearer grt_abc"} {
		if HasTokenPrefix(s) {
			t.Errorf("HasTokenPrefix(%q) = true, want false", s)
		}
	}
}
