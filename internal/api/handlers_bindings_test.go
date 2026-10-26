package api

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// TestValidateExpiresAt фиксирует правило срока действия binding: момент в
// прошлом — отказ, а не молча выданный бессрочно работающий доступ.
//
// До этого истёкший expires_at принимался, грант применялся и получал
// synced; отзыв зависел от того, когда сработает прогон обслуживания.
func TestValidateExpiresAt(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		value   *time.Time
		wantErr bool
	}{
		{name: "nil is a permanent binding", value: nil},
		{name: "future", value: ptrTime(now.Add(time.Hour))},
		{name: "past", value: ptrTime(now.Add(-time.Hour)), wantErr: true},
		{name: "exactly now", value: ptrTime(now), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExpiresAt(tt.value, now)
			if tt.wantErr != (err != nil) {
				t.Errorf("validateExpiresAt(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestWeakAuthGrantCheck фиксирует гейт на учётку без пароля: право такой
// учётке фактически выдаётся всем, кто знает её имя, поэтому оператор обязан
// подтвердить это явно.
func TestWeakAuthGrantCheck(t *testing.T) {
	nopass := inventory.Account{
		EngineIdentity: "svc",
		Attributes:     json.RawMessage(`{"nopass": true, "has_password": false}`),
	}
	normal := inventory.Account{
		EngineIdentity: "svc",
		Attributes:     json.RawMessage(`{"nopass": false, "has_password": true}`),
	}
	noAttrs := inventory.Account{EngineIdentity: "svc"}

	if err := weakAuthGrantCheck(nopass, false); !errors.Is(err, errWeakAuthNotConfirmed) {
		t.Errorf("nopass without confirm: error = %v, want errWeakAuthNotConfirmed", err)
	}
	if err := weakAuthGrantCheck(nopass, true); err != nil {
		t.Errorf("nopass with confirm: error = %v, want nil", err)
	}
	if err := weakAuthGrantCheck(normal, false); err != nil {
		t.Errorf("account with a password: error = %v, want nil", err)
	}
	// Движок, который про nopass ничего не сообщает, не должен требовать
	// подтверждения: молчание не доказывает слабую аутентификацию.
	if err := weakAuthGrantCheck(noAttrs, false); err != nil {
		t.Errorf("account without attributes: error = %v, want nil", err)
	}
}
