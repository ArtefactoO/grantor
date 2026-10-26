package mysql

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотация из discover.go: имя роли — userHostIdentity (`user@host`), host и
// глобальные привилегии лежат в атрибутах.
func TestNormalizePermission(t *testing.T) {
	ad := New()

	t.Run("host moves into scope", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "role:app_ro@%",
			Name:       "app_ro@%",
			Assignable: true,
			Attributes: map[string]any{"host": "%"},
		})
		if view.Resource != "app_ro" {
			t.Errorf("Resource = %q, want the role name without host", view.Resource)
		}
		if view.Scope != "%" {
			t.Errorf("Scope = %q, want the host", view.Scope)
		}
		// Raw остаётся полным: именно его пользователь копирует.
		if view.Raw != "app_ro@%" {
			t.Errorf("Raw = %q, want the full identity", view.Raw)
		}
	})

	t.Run("danger reason names the privileges", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "role:ops@10.0.0.%",
			Name:       "ops@10.0.0.%",
			Dangerous:  true,
			Attributes: map[string]any{
				"host":              "10.0.0.%",
				"global_privileges": []string{"SELECT", "SUPER", "ROLE_ADMIN"},
			},
		})
		want := "grants administrative privileges: ROLE_ADMIN, SUPER"
		if view.DangerReason != want {
			t.Errorf("DangerReason = %q, want %q", view.DangerReason, want)
		}
	})

	// Атрибуты, пришедшие из БД, теряют тип []string и становятся []any —
	// нормализация обязана понимать оба варианта.
	t.Run("privileges survive a json round trip", func(t *testing.T) {
		view := New().NormalizePermission(adapter.PermissionRef{
			Name:      "ops@%",
			Dangerous: true,
			Attributes: map[string]any{
				"host":              "%",
				"global_privileges": []any{"SUPER"},
			},
		})
		if view.DangerReason != "grants administrative privileges: SUPER" {
			t.Errorf("DangerReason = %q, want the privilege parsed from []any", view.DangerReason)
		}
	})
}
