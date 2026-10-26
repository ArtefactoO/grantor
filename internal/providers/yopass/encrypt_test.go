package yopass

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Расшифровка и совместимость: сообщение обязано читаться классическим
// OpenPGP-ридером и round-trip'ить исходный plaintext.
func TestEncryptClassicRoundTrip(t *testing.T) {
	const key = "test-key-123"
	plaintext := []byte("username: svc\npassword: p@ss")

	armored, err := encryptClassic(plaintext, key)
	if err != nil {
		t.Fatalf("encryptClassic: %v", err)
	}
	if !strings.HasPrefix(armored, "-----BEGIN PGP MESSAGE-----") {
		t.Fatalf("output is not an armored PGP message: %q", armored[:40])
	}

	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		t.Fatalf("armor decode: %v", err)
	}
	md, err := openpgp.ReadMessage(block.Body, nil,
		func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if !symmetric {
				return nil, errors.New("expected symmetric message")
			}
			return []byte(key), nil
		}, nil)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	got, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip = %q, want %q", got, plaintext)
	}
}

// Формат: пакет должен быть SEIPDv1 (классический, с MDC), а не AEAD
// (SEIPDv2) — иначе старые web-клиенты Yopass не смогут расшифровать.
func TestEncryptClassicIsNotAEAD(t *testing.T) {
	armored, err := encryptClassic([]byte("x"), "k")
	if err != nil {
		t.Fatalf("encryptClassic: %v", err)
	}
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		t.Fatalf("armor decode: %v", err)
	}
	reader := packet.NewReader(block.Body)
	sawSEIPDv1 := false
	for {
		p, err := reader.Next()
		if err != nil {
			break
		}
		if se, ok := p.(*packet.SymmetricallyEncrypted); ok {
			if se.Version != 1 {
				t.Fatalf("SymmetricallyEncrypted version = %d, want 1 (classic SEIPDv1)", se.Version)
			}
			sawSEIPDv1 = true
			break
		}
	}
	if !sawSEIPDv1 {
		t.Fatal("no SymmetricallyEncrypted packet found in message")
	}
}

func TestEncryptClassicEmptyKey(t *testing.T) {
	if _, err := encryptClassic([]byte("x"), ""); err == nil {
		t.Fatal("empty key: err = nil, want error")
	}
}
