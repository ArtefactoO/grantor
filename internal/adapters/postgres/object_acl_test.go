package postgres

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestObjectACLStatementsQuoteCatalogIdentifiers(t *testing.T) {
	p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11,
		Name: `items"; DROP TABLE victims; --`, ObjectOID: 12, OwnerOID: 13, Privilege: "SELECT"}
	statement, err := objectACLTargetSQL(p)
	if err != nil || statement != `table "public"."items""; DROP TABLE victims; --"` {
		t.Fatalf("catalog identifier escaped its SQL token: %q %v", statement, err)
	}
	p.Privilege = "SELECT; DROP TABLE victims"
	if _, err := objectACLTargetSQL(p); err == nil {
		t.Fatal("unreviewed action was interpolated into SQL")
	}
}
