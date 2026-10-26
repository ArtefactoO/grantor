package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/credentials"
)

// Инвертированная семантика проверки метаданных однажды уронила всю секцию
// «Credential по окружениям» из-за одного 403 от Vault; фиксация fail-open —
// регрессионный контракт.
func TestFillConfiguredKeepsListOnRowError(t *testing.T) {
	principalID := uuid.New()
	items := []principalCredentialEnvironmentJSON{
		{Environment: "broken"},
		{Environment: "ok"},
	}
	err := fillConfigured(t.Context(), principalID, items,
		func(_ context.Context, _ uuid.UUID, env string) (bool, error) {
			if env == "broken" {
				return false, errors.New("permission denied")
			}
			return true, nil
		})
	if err != nil {
		t.Fatalf("fillConfigured() error = %v, want nil", err)
	}
	if items[0].Configured != nil {
		t.Errorf("broken environment configured = %v, want nil (unknown)", *items[0].Configured)
	}
	if items[1].Configured == nil || !*items[1].Configured {
		t.Error("ok environment configured != true")
	}
}

func TestFillConfiguredFailsWithoutVault(t *testing.T) {
	items := []principalCredentialEnvironmentJSON{{Environment: "prod"}}
	err := fillConfigured(t.Context(), uuid.New(), items,
		func(context.Context, uuid.UUID, string) (bool, error) {
			return false, credentials.ErrVaultNotConfigured
		})
	if !errors.Is(err, credentials.ErrVaultNotConfigured) {
		t.Fatalf("fillConfigured() error = %v, want ErrVaultNotConfigured", err)
	}
}

// Фронт различает false («нет креда») и null («неизвестно»), поэтому wire-
// формат тристейта фиксируется явно.
func TestPrincipalCredentialJSONTriState(t *testing.T) {
	configured := false
	raw, err := json.Marshal([]principalCredentialEnvironmentJSON{
		{Environment: "known", Configured: &configured},
		{Environment: "unknown"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if v, ok := decoded[0]["configured"].(bool); !ok || v {
		t.Errorf("known configured = %v, want false", decoded[0]["configured"])
	}
	if decoded[1]["configured"] != nil {
		t.Errorf("unknown configured = %v, want null", decoded[1]["configured"])
	}
}
