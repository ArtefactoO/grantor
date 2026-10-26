package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func validDatabaseWithRolesRequest() createDatabaseWithRolesRequest {
	return createDatabaseWithRolesRequest{
		createResourceRequest: createResourceRequest{Name: "appdb", Owner: "app_owner"},
		CreateDefaultRoles:    true, RequestID: uuid.New(), UpdatedAt: time.Now(), ExpectedTargetIdentity: "postgres:system:12345",
	}
}

func TestDatabaseWithRolesRequest(t *testing.T) {
	for _, name := range []string{"appdb", "_db", "App_123", strings.Repeat("a", 60)} {
		req := validDatabaseWithRolesRequest()
		req.Name = name
		if err := req.validate(); err != nil {
			t.Fatalf("valid %q: %v", name, err)
		}
	}
	for _, name := range []string{"", "1db", "db-name", "db.name", "база", strings.Repeat("a", 61)} {
		req := validDatabaseWithRolesRequest()
		req.Name = name
		if err := req.validate(); err == nil {
			t.Fatalf("accepted non-portable/too-long database %q", name)
		}
	}
	for _, mutate := range []func(*createDatabaseWithRolesRequest){
		func(r *createDatabaseWithRolesRequest) { r.CreateDefaultRoles = false },
		func(r *createDatabaseWithRolesRequest) { r.RequestID = uuid.Nil },
		func(r *createDatabaseWithRolesRequest) { r.UpdatedAt = time.Time{} },
		func(r *createDatabaseWithRolesRequest) { r.ExpectedTargetIdentity = "" },
		func(r *createDatabaseWithRolesRequest) { r.Owner = "" },
		func(r *createDatabaseWithRolesRequest) { r.Owner = "owner-name" },
		func(r *createDatabaseWithRolesRequest) { r.Owner = strings.Repeat("a", 64) },
	} {
		req := validDatabaseWithRolesRequest()
		mutate(&req)
		if err := req.validate(); err == nil {
			t.Fatal("accepted incomplete/unsafe default-role request")
		}
	}
	template0 := validDatabaseWithRolesRequest()
	template0.Template = " template0 "
	if err := template0.validate(); err != nil {
		t.Fatalf("template0 no longer carries a persistent helper contract: %v", err)
	}
}
