//go:build integration

// Integration-тест клиента Yopass против реального сервера
// (GRANTOR_TEST_YOPASS_ADDR, поднимается harness-скриптом
// scripts/test-integration.sh; без переменной тест пропускается).
package yopass_test

import (
	"os"
	"strings"
	"testing"

	yopassapi "github.com/jhaals/yopass/pkg/yopass"

	"github.com/ArtefactoO/grantor/internal/providers/yopass"
)

func TestShareRoundTrip(t *testing.T) {
	addr := os.Getenv("GRANTOR_TEST_YOPASS_ADDR")
	if addr == "" {
		t.Skip("GRANTOR_TEST_YOPASS_ADDR is not set; skipping yopass integration test")
	}

	c, err := yopass.New(yopass.Config{APIURL: addr, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("yopass.New: %v", err)
	}

	const message = "username: itest\npassword: itest-secret-marker"
	link, err := c.Share(t.Context(), []byte(message), 3600, true)
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if !strings.HasPrefix(link, "http://localhost:58090/#/s/") {
		t.Fatalf("link = %q, want yopass web format", link)
	}

	// Ссылка расшифровывается обратно в исходное сообщение.
	id, key, fileOpt, keyOpt, err := yopassapi.ParseURL(link)
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	if fileOpt || keyOpt || key == "" {
		t.Fatalf("unexpected link options: file=%v manual-key=%v", fileOpt, keyOpt)
	}
	ciphertext, err := yopassapi.Fetch(addr, id)
	if err != nil {
		t.Fatalf("fetch secret: %v", err)
	}
	plaintext, _, err := yopassapi.Decrypt(strings.NewReader(ciphertext), key)
	if err != nil {
		t.Fatalf("decrypt secret: %v", err)
	}
	if plaintext != message {
		t.Errorf("decrypted message = %q, want %q", plaintext, message)
	}

	// one_time: повторное чтение того же секрета невозможно.
	if _, err := yopassapi.Fetch(addr, id); err == nil {
		t.Error("second fetch of one-time secret succeeded, want error")
	}
}
