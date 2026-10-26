package postgres

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотации взяты из discover.go: назначаемая роль с флагами и наблюдаемое
// членство login-роли.
func TestNormalizePermission(t *testing.T) {
	ad := New()

	cases := []struct {
		name         string
		ref          adapter.PermissionRef
		wantResource string
		wantRaw      string
		wantReason   string
	}{
		{
			name: "plain role",
			ref: adapter.PermissionRef{
				ExternalID: "role:app_readonly",
				Name:       "app_readonly",
				Assignable: true,
				Attributes: map[string]any{
					"superuser": false, "createdb": false, "createrole": false,
					"replication": false, "bypassrls": false,
				},
			},
			wantResource: "app_readonly",
			wantRaw:      "app_readonly",
		},
		{
			// Причина обязана называть те флаги, из-за которых роль и
			// помечена опасной, а не общие слова.
			name: "superuser role explains the flags",
			ref: adapter.PermissionRef{
				ExternalID: "role:ops",
				Name:       "ops",
				Assignable: true,
				Dangerous:  true,
				Attributes: map[string]any{
					"superuser": true, "createrole": true, "createdb": true,
					"replication": false, "bypassrls": false,
				},
			},
			wantResource: "ops",
			wantRaw:      "ops",
			wantReason: "superuser: bypasses all permission checks; " +
				"can create and alter roles, including granting itself membership",
		},
		{
			// Историческая запись без атрибутов: причину выдумывать нельзя.
			name: "dangerous role without attributes falls back to a generic reason",
			ref: adapter.PermissionRef{
				ExternalID: "role:legacy",
				Name:       "legacy",
				Dangerous:  true,
			},
			wantResource: "legacy",
			wantRaw:      "legacy",
			wantReason:   "the engine marks this role as dangerous",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := adaptertest.CheckPermissionNormalization(t, ad, tc.ref)
			if view.Category != adapter.PermissionRole {
				t.Errorf("Category = %q, want role", view.Category)
			}
			if view.Resource != tc.wantResource {
				t.Errorf("Resource = %q, want %q", view.Resource, tc.wantResource)
			}
			if view.Raw != tc.wantRaw {
				t.Errorf("Raw = %q, want %q", view.Raw, tc.wantRaw)
			}
			if view.DangerReason != tc.wantReason {
				t.Errorf("DangerReason = %q, want %q", view.DangerReason, tc.wantReason)
			}
		})
	}
}

// Флаги со значением false не попадают в детали: строка «superuser: false»
// ничего не сообщает и лишь удлиняет панель подробностей.
func TestNormalizePermissionShowsOnlySetFlags(t *testing.T) {
	view := New().NormalizePermission(adapter.PermissionRef{
		Name: "ops",
		Attributes: map[string]any{
			"superuser": false, "createdb": true, "createrole": false,
		},
	})
	if len(view.Details) != 1 {
		t.Fatalf("Details = %+v, want only the flags that are set", view.Details)
	}
	if view.Details[0].Key != "createdb" {
		t.Errorf("Details[0].Key = %q, want createdb", view.Details[0].Key)
	}
}
