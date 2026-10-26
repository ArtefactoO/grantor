package mongodb

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотация из discover.go: имя permission — имя роли, база роли лежит в
// атрибуте role_db.
func TestNormalizePermission(t *testing.T) {
	ad := New()

	t.Run("role db becomes the scope", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "role:ads:readWrite",
			Name:       "readWrite",
			Assignable: true,
			Attributes: map[string]any{"role_db": "ads", "builtin": true},
		})
		if view.Resource != "readWrite" || view.Scope != "ads" {
			t.Errorf("Resource/Scope = %q/%q, want readWrite/ads", view.Resource, view.Scope)
		}
	})

	// Одноимённая роль в разных базах — разные права; без базы подпись
	// неоднозначна, поэтому scope берётся даже когда scope-ресурса нет.
	t.Run("scope falls back to role db", func(t *testing.T) {
		view := New().NormalizePermission(adapter.PermissionRef{
			Name:       "readWrite",
			Attributes: map[string]any{"role_db": "billing"},
		})
		if view.Scope != "billing" {
			t.Errorf("Scope = %q, want billing", view.Scope)
		}
	})

	t.Run("built-in administrative role is explained by name", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "role:admin:root",
			Name:       "root",
			Dangerous:  true,
			Attributes: map[string]any{"role_db": "admin", "builtin": true},
		})
		if view.DangerReason != "built-in administrative role: root" {
			t.Errorf("DangerReason = %q, want the role named", view.DangerReason)
		}
	})

	t.Run("inherited roles are listed", func(t *testing.T) {
		view := New().NormalizePermission(adapter.PermissionRef{
			Name: "app_rw",
			Attributes: map[string]any{
				"role_db":         "ads",
				"inherited_roles": []string{"read", "readWrite"},
			},
		})
		var got string
		for _, d := range view.Details {
			if d.Key == "inherited_roles" {
				got = d.Value
			}
		}
		if got != "read, readWrite" {
			t.Errorf("inherited_roles detail = %q, want %q", got, "read, readWrite")
		}
	})
}
