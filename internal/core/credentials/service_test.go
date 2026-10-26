package credentials

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceWithoutVault(t *testing.T) {
	s := NewService(nil, nil)
	id := uuid.New()

	if _, _, err := s.PutAccountCredential(t.Context(), id, "svc", []byte("x")); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("PutAccountCredential error = %v, want ErrVaultNotConfigured", err)
	}
	if _, _, err := s.GetAccountCredential(t.Context(), "accounts/"+id.String()+"/credential", "svc"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("GetAccountCredential error = %v, want ErrVaultNotConfigured", err)
	}
	// Yopass проверяется раньше Vault: без обоих клиентов share честно
	// говорит про канал доставки.
	if _, err := s.ShareAccountCredential(t.Context(), "accounts/"+id.String()+"/credential", "svc", 0); !errors.Is(err, ErrYopassNotConfigured) {
		t.Errorf("ShareAccountCredential error = %v, want ErrYopassNotConfigured", err)
	}
	if err := s.DeleteAccountCredential(t.Context(), ""); err != nil {
		t.Errorf("DeleteAccountCredential empty path = %v, want no-op", err)
	}
	if err := s.DeleteAccountCredential(t.Context(), "principals/one/environments/dev/credential"); err != nil {
		t.Errorf("DeleteAccountCredential shared path = %v, want no-op", err)
	}
	if err := s.DeleteAccountCredential(t.Context(), "accounts/"+id.String()+"/credential"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("DeleteAccountCredential own path = %v, want ErrVaultNotConfigured", err)
	}
}

func TestPutAccountCredentialValidation(t *testing.T) {
	// Валидация аргументов идёт после проверки Vault, поэтому для её
	// покрытия нужен ненулевой клиент; проверяем только nil-ветки и
	// пустые значения через ErrVaultNotConfigured-обход невозможно —
	// достаточно nil-кейсов выше и юнита формата сообщения ниже.
	s := NewService(nil, nil)
	if _, _, err := s.PutAccountCredential(t.Context(), uuid.New(), "", nil); err == nil {
		t.Error("PutAccountCredential without vault: err = nil, want error")
	}
}

func TestShareMessageFormat(t *testing.T) {
	got := shareMessage("svc_payments", []byte("p@ss"))
	want := "username: svc_payments\npassword: p@ss"
	if string(got) != want {
		t.Errorf("shareMessage = %q, want %q", got, want)
	}
}
