package redis

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотации из discover.go: назначаемые bundle (read/write/admin) и сырые
// ACL-правила неуправляемых пользователей (`acl:<правила>`).
func TestNormalizePermission(t *testing.T) {
	ad := New()

	t.Run("bundle", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: bundleRead,
			Name:       bundleRead,
			Assignable: true,
			Attributes: map[string]any{
				"kind": "bundle", "rules": "~* &* +@read -@dangerous",
			},
		})
		if view.Category != adapter.PermissionBundle {
			t.Errorf("Category = %q, want bundle", view.Category)
		}
		if view.Action != bundleRead {
			t.Errorf("Action = %q, want %q", view.Action, bundleRead)
		}
	})

	// Главное, ради чего нормализация нужна Redis: плоская строка правил
	// раскладывается по видам, иначе её приходится разбирать глазами.
	t.Run("rules are split by kind of token", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: rawPermissionPrefix + "~cache:* &events +@read -@dangerous +get",
			Name:       rawPermissionPrefix + "~cache:* &events +@read -@dangerous +get",
			Attributes: map[string]any{
				"kind":  "acl",
				"rules": "~cache:* &events +@read -@dangerous +get",
			},
		})
		if view.Category != adapter.PermissionACL {
			t.Errorf("Category = %q, want acl", view.Category)
		}
		got := map[string]string{}
		order := make([]string, 0, len(view.Details))
		for _, d := range view.Details {
			got[d.Key] = d.Value
			order = append(order, d.Key)
		}
		want := map[string]string{
			"key_patterns": "~cache:*",
			"channels":     "&events",
			"categories":   "+@read -@dangerous",
			"commands":     "+get",
		}
		for key, value := range want {
			if got[key] != value {
				t.Errorf("detail %q = %q, want %q", key, got[key], value)
			}
		}
		// Порядок видов фиксирован и не зависит от порядка токенов.
		wantOrder := []string{"key_patterns", "channels", "categories", "commands"}
		for i, key := range wantOrder {
			if i >= len(order) || order[i] != key {
				t.Errorf("detail order = %v, want %v", order, wantOrder)
				break
			}
		}
	})

	// Порядок правил внутри вида значим: Redis применяет их последовательно,
	// и `+@all -@admin` не равно `-@admin +@all`.
	t.Run("order inside a kind is preserved", func(t *testing.T) {
		view := New().NormalizePermission(adapter.PermissionRef{
			Name:       "acl:x",
			Attributes: map[string]any{"kind": "acl", "rules": "+@all -@admin"},
		})
		for _, d := range view.Details {
			if d.Key == "categories" && d.Value != "+@all -@admin" {
				t.Errorf("categories = %q, want the original order", d.Value)
			}
		}
	})

	// Незнакомый токен не выбрасывается: потерять правило хуже, чем показать
	// его неразобранным.
	t.Run("unrecognized token is kept", func(t *testing.T) {
		view := New().NormalizePermission(adapter.PermissionRef{
			Name:       "acl:x",
			Attributes: map[string]any{"kind": "acl", "rules": "~* resetchannels"},
		})
		var other string
		for _, d := range view.Details {
			if d.Key == "other_rules" {
				other = d.Value
			}
		}
		if other != "resetchannels" {
			t.Errorf("other_rules = %q, want the unrecognized token kept", other)
		}
	})
}
