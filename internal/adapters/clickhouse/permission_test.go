package clickhouse

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотации из discover.go: назначаемая роль (kind=role) и наблюдаемый прямой
// грант (kind=privilege, имя `<ACCESS TYPE> ON <db>.*`).
func TestNormalizePermission(t *testing.T) {
	ad := New()

	t.Run("role lists its privileges", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "role:analytics_ro",
			Name:       "analytics_ro",
			Assignable: true,
			Attributes: map[string]any{
				"kind":       "role",
				"privileges": []string{"SELECT ON ads.*"},
			},
		})
		if view.Category != adapter.PermissionRole {
			t.Errorf("Category = %q, want role", view.Category)
		}
		var privs string
		for _, d := range view.Details {
			if d.Key == "privileges" {
				privs = d.Value
			}
		}
		if privs != "SELECT ON ads.*" {
			t.Errorf("privileges detail = %q, want the grant", privs)
		}
	})

	// Прямой грант отличается от роли: им нельзя управлять из grantor, и
	// категория обязана это показывать.
	t.Run("direct grant is a privilege, not a role", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "priv:SELECT:ads",
			Name:       "SELECT ON ads.*",
			Attributes: map[string]any{
				"kind": "privilege", "access_type": "SELECT", "database": "ads",
			},
		})
		if view.Category != adapter.PermissionPrivilege {
			t.Errorf("Category = %q, want privilege", view.Category)
		}
		if view.Action != "SELECT" || view.Scope != "ads" {
			t.Errorf("Action/Scope = %q/%q, want SELECT/ads", view.Action, view.Scope)
		}
	})

	t.Run("grant without a database is cluster wide", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "priv:ALL:",
			Name:       "ALL ON *.*",
			Dangerous:  true,
			Attributes: map[string]any{"kind": "privilege", "access_type": "ALL"},
		})
		if view.Scope != "*.*" {
			t.Errorf("Scope = %q, want *.*", view.Scope)
		}
		if view.DangerReason != "cluster-wide grant of ALL" {
			t.Errorf("DangerReason = %q, want the cluster-wide explanation", view.DangerReason)
		}
	})

	// formatGrant дописывает к гранту хвост WITH GRANT OPTION; без его
	// отбрасывания грант на *.* не распознавался бы как кластерный.
	t.Run("role danger reason parses grants with a trailing clause", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "role:ops",
			Name:       "ops",
			Dangerous:  true,
			Attributes: map[string]any{
				"kind":       "role",
				"privileges": []string{"SELECT ON ads.*", "ALL ON *.* WITH GRANT OPTION"},
			},
		})
		want := "grants administrative privileges: ALL ON *.* WITH GRANT OPTION"
		if view.DangerReason != want {
			t.Errorf("DangerReason = %q, want %q", view.DangerReason, want)
		}
	})
}
