package adapter

import "testing"

func TestPostgresSuperuserDirectVocabularyIsClosedAndDistinct(t *testing.T) {
	kinds := []ChangeKind{
		ChangePostgresAccountCreateV2,
		ChangePostgresAccountRestoreV2,
		ChangePostgresRoleCreateV2,
		ChangePostgresDatabaseCreateV2,
		ChangePostgresRolePolicyApplyV2,
		ChangePostgresRolePolicyVerifyV2,
		ChangePostgresRolePolicyAdoptV2,
		ChangePostgresRolePolicyRepairV2,
		ChangePostgresRolePolicyCreateV2,
		ChangePostgresRolePolicyCreateDatabaseV2,
	}
	seen := make(map[ChangeKind]struct{}, len(kinds))
	for _, kind := range kinds {
		if !IsPostgresSuperuserDirectChange(kind) {
			t.Fatalf("PostgreSQL v2 kind %q is outside its closed classifier", kind)
		}
		if _, duplicate := seen[kind]; duplicate {
			t.Fatalf("duplicate PostgreSQL v2 kind %q", kind)
		}
		seen[kind] = struct{}{}
	}
	for _, generic := range []ChangeKind{
		ChangeAccountCreate, ChangeAccountRestore, ChangeRoleCreate,
		ChangeResourceCreate, ChangeRolePolicyApply, ChangeRolePolicyVerify,
		ChangeRolePolicyCreate, ChangeRolePolicyCreateDatabase,
	} {
		if IsPostgresSuperuserDirectChange(generic) {
			t.Fatalf("generic kind %q collided with PostgreSQL v2 vocabulary", generic)
		}
		if _, collision := seen[generic]; collision {
			t.Fatalf("generic kind %q equals a PostgreSQL v2 kind", generic)
		}
	}
	if CapPostgresSuperuserDirectV1 == CapAccountCreate ||
		CapPostgresSuperuserDirectV1 == CapRolePolicyApply {
		t.Fatalf("PostgreSQL authority marker %q collides with a generic capability", CapPostgresSuperuserDirectV1)
	}
}
