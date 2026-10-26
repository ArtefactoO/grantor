package postgres

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestDatabaseRolePolicyOIDCannotBeSilentlyIgnored(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{adapter.ChangeRolePolicyCreate, adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify} {
		if err := validateRolePolicyChange(adapter.DesiredChange{Kind: kind, ExpectedDatabaseOID: 100}); err == nil {
			t.Fatalf("%s accepted database OID intended for a new protocol kind", kind)
		}
		if err := validateRolePolicyChange(adapter.DesiredChange{Kind: kind, Resource: &adapter.ResourceSpec{Kind: "database"}}); err == nil {
			t.Fatalf("%s accepted resource spec", kind)
		}
	}
	if err := validateRolePolicyChange(adapter.DesiredChange{Kind: adapter.ChangeRolePolicyCreateDatabase}); err == nil {
		t.Fatal("new database policy kind accepted an unpinned database")
	}
	if err := validateRolePolicyChange(adapter.DesiredChange{Kind: adapter.ChangeRolePolicyCreateDatabase, ExpectedDatabaseOID: 100,
		RolePolicySpec: &adapter.RolePolicySpec{OwnerRoles: []string{"owner"}, CreatorRoles: []string{"owner"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseRolePolicyRequiresSingleFrozenOwner(t *testing.T) {
	for _, spec := range []*adapter.RolePolicySpec{
		nil,
		{OwnerRoles: []string{"owner"}},
		{OwnerRoles: []string{"owner"}, CreatorRoles: []string{"another"}},
		{OwnerRoles: []string{"owner", "another"}, CreatorRoles: []string{"owner"}},
		{OwnerRoles: []string{"owner"}, CreatorRoles: []string{"owner", "another"}},
	} {
		change := adapter.DesiredChange{Kind: adapter.ChangeRolePolicyCreateDatabase, ExpectedDatabaseOID: 100, RolePolicySpec: spec}
		if err := validateRolePolicyChange(change); err == nil {
			t.Fatalf("database policy accepted ambiguous owner scope: %+v", spec)
		}
		change.Kind, change.ExpectedDatabaseOID = adapter.ChangeRolePolicyCreate, 0
		if err := validateRolePolicyChange(change); err != nil {
			t.Fatalf("generic policy change unexpectedly narrowed: %v", err)
		}
	}
}
