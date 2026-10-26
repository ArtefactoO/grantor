//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestIntegrationInventoryFreshnessSurvivesPolicyCompletionUntilDiscovery(t *testing.T) {
	env := newTestEnv(t, nil)
	conn, original := seedRolePolicyAPI(t, env)
	if original.ObservedAt == nil {
		t.Fatal("fixture has no policy observation")
	}
	snapshotAt := *original.ObservedAt
	if _, err := env.pool.Exec(t.Context(), `update connections set last_discovery_at=$2 where id=$1`, conn.ID, snapshotAt); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `update permission_definitions set attributes=attributes || '{"role_oid":19}'::jsonb where connection_id=$1 and external_id=$2`, conn.ID, original.ExternalID); err != nil {
		t.Fatal(err)
	}
	admin := session(auth.RoleAdmin)
	basePath := "/api/v1/connections/" + conn.ID.String()
	readFreshness := func(path, wantStatus string, version int64) {
		t.Helper()
		response := env.do(t, http.MethodGet, basePath+path, nil, &admin, false)
		requireStatus(t, response, http.StatusOK)
		var got struct {
			Inventory struct {
				Status          string           `json:"status"`
				ObservedAt      *time.Time       `json:"observed_at"`
				SnapshotVersion string           `json:"snapshot_version"`
				RefreshRequired bool             `json:"refresh_required"`
				Reason          string           `json:"reason"`
				PolicyVersions  map[string]int64 `json:"role_policy_versions"`
			} `json:"inventory"`
			Permissions []struct {
				ExternalID string `json:"external_id"`
				Assignable bool   `json:"assignable"`
				Attributes struct {
					RoleOID int `json:"role_oid"`
				} `json:"attributes"`
			} `json:"permissions"`
		}
		if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Inventory.Status != wantStatus || got.Inventory.RefreshRequired != (wantStatus != "current") ||
			got.Inventory.ObservedAt == nil || !got.Inventory.ObservedAt.Equal(snapshotAt) ||
			got.Inventory.SnapshotVersion != snapshotAt.UTC().Format(time.RFC3339Nano) || got.Inventory.PolicyVersions[original.TemplateKey] != version {
			t.Fatalf("%s freshness = %+v", path, got.Inventory)
		}
		if wantStatus == "stale" && got.Inventory.Reason != "role_policy_newer_than_inventory" {
			t.Fatalf("policy mutation did not identify stale permission attributes: %+v", got.Inventory)
		}
		if path == "/permissions" {
			found := false
			for _, permission := range got.Permissions {
				if permission.ExternalID == original.ExternalID {
					found = true
					if permission.Attributes.RoleOID != 19 || (version > original.Version && !permission.Assignable) {
						t.Fatalf("permission lost snapshot attributes or completed assignability: %+v", permission)
					}
				}
			}
			if !found {
				t.Fatal("policy permission absent from list")
			}
		}
	}
	readFreshness("/role-policies", "current", original.Version)
	readFreshness("/permissions", "current", original.Version)
	tx, err := env.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	op, _, err := operations.NewStore().Create(t.Context(), tx, operations.CreateParams{
		Kind: jobs.KindPostgresRolePolicyAdoptV2, ConnectionID: &conn.ID, ActorType: "test", ActorID: t.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := rolepolicies.NewStore().Reserve(t.Context(), tx, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: original.TemplateKey, Action: rolepolicies.ActionAdopt,
		OperationID: op.ID, Version: original.Version, ObservedFingerprint: original.ObservedFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := rolepolicies.NewStore().Complete(t.Context(), tx, op.ID, reserved.ExpectedVersion,
		original.ObservedFingerprint, original.ExpectedFingerprint, original.DesiredSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	readFreshness("/role-policies", "stale", completed.Version)
	readFreshness("/permissions", "stale", completed.Version)
	if completed.ObservedAt == nil || !completed.ObservedAt.After(snapshotAt) {
		t.Fatal("Complete did not advance the role-policy observation")
	}
	// A discovery owns both inventory and role-policy observations. Only that
	// shared timestamp makes the completed version current for ACL readers.
	snapshotAt = completed.ObservedAt.Add(time.Second)
	if err := rolepolicies.NewStore().ReconcileSnapshot(t.Context(), env.pool, conn.ID, []adapter.ObservedRolePolicy{{
		ExternalID: original.ExternalID, Spec: original.DesiredSpec, ExpectedFingerprint: original.ExpectedFingerprint,
		ObservedFingerprint: original.ExpectedFingerprint, Exact: true, ApplySupported: true,
		Summary: map[string]any{"role": map[string]any{"exists": true, "safe": true}},
	}}, snapshotAt); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set last_discovery_at=$2 where id=$1`, conn.ID, snapshotAt); err != nil {
		t.Fatal(err)
	}
	refreshed, err := rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, original.TemplateKey)
	if err != nil {
		t.Fatal(err)
	}
	readFreshness("/role-policies", "current", refreshed.Version)
	readFreshness("/permissions", "current", refreshed.Version)
	var count int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from role_policy_operation_completions where operation_id=$1`, op.ID).Scan(&count); err != nil || count != 1 || op.ID == uuid.Nil {
		t.Fatalf("completion receipt missing: count=%d err=%v", count, err)
	}
}

func TestIntegrationInventoryFreshnessUsesActualTransitionActivity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       operations.Status
		retryPending bool
		active       bool
	}{
		{"approval waiting", operations.StatusPendingApproval, true, true},
		{"queued", operations.StatusPending, true, true},
		{"running", operations.StatusRunning, true, true},
		{"failed automatic retry pending", operations.StatusFailed, true, true},
		{"failed retries exhausted", operations.StatusFailed, false, false},
		{"cancelled", operations.StatusCancelled, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn, policy := seedPostgresProfilesConnection(t, env)
			op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
				Kind: jobs.KindPostgresRolePolicyAdoptV2, ConnectionID: &conn.ID, ActorType: "test", ActorID: t.Name(),
			})
			if err != nil {
				t.Fatal(err)
			}
			reserved, err := rolepolicies.NewStore().Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{
				ConnectionID: conn.ID, TemplateKey: policy.TemplateKey, Action: rolepolicies.ActionAdopt,
				OperationID: op.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := env.pool.Exec(t.Context(), `update operations set status=$2 where id=$1`, op.ID, tc.status); err != nil {
				t.Fatal(err)
			}
			if tc.status == operations.StatusFailed {
				if err := rolepolicies.NewStore().MarkFailed(t.Context(), env.pool, op.ID, reserved.ExpectedVersion); err != nil {
					t.Fatal(err)
				}
				if !tc.retryPending {
					if err := rolepolicies.NewStore().MarkRetryExhausted(t.Context(), env.pool, op.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			observedAt := time.Now().UTC().Truncate(time.Microsecond)
			if err := rolepolicies.NewStore().ReconcileSnapshot(t.Context(), env.pool, conn.ID, []adapter.ObservedRolePolicy{{
				ExternalID: policy.ExternalID, Spec: policy.DesiredSpec, ExpectedFingerprint: policy.ExpectedFingerprint,
				ObservedFingerprint: policy.ObservedFingerprint, Exact: true, ApplySupported: true,
				Summary: map[string]any{"role": map[string]any{"exists": true, "safe": true}},
			}}, observedAt); err != nil {
				t.Fatal(err)
			}
			if _, err := env.pool.Exec(t.Context(), `update connections set last_discovery_at=$2,topology=topology || '{"postgres_object_acl_version":1,"postgres_default_privileges":[]}'::jsonb where id=$1`, conn.ID, observedAt); err != nil {
				t.Fatal(err)
			}
			var accountID uuid.UUID
			if err := env.pool.QueryRow(t.Context(), `select id from accounts where connection_id=$1 and engine_identity='app_owner'`, conn.ID).Scan(&accountID); err != nil {
				t.Fatal(err)
			}
			base := "/api/v1/connections/" + conn.ID.String()
			account := "/api/v1/accounts/" + accountID.String()
			admin := session(auth.RoleAdmin)
			for _, path := range []string{
				base + "/role-policies", base + "/permissions", account + "/object-privileges", account + "/default-privileges",
				account + "/postgres/access-diagnostics?database=app&profile=read&source_ip=10.1.2.3&tls=true",
			} {
				response := env.do(t, http.MethodGet, path, nil, &admin, false)
				requireStatus(t, response, http.StatusOK)
				var page struct {
					Inventory struct {
						Status          string `json:"status"`
						Reason          string `json:"reason"`
						RefreshRequired bool   `json:"refresh_required"`
					} `json:"inventory"`
				}
				if err := json.Unmarshal(readBody(t, response), &page); err != nil {
					t.Fatal(err)
				}
				wantStatus := "current"
				if tc.active {
					wantStatus = "stale"
				}
				if page.Inventory.Status != wantStatus || page.Inventory.RefreshRequired != tc.active ||
					(tc.active && page.Inventory.Reason != "role_policy_transition_in_progress") {
					t.Fatalf("%s: %+v, active=%v", path, page.Inventory, tc.active)
				}
			}
			wantStatus := http.StatusAccepted
			if tc.active {
				wantStatus = http.StatusConflict
			}
			requireStatus(t, env.do(t, http.MethodPost, base+"/postgres/access-profiles", standardProfilesBody(), &admin, true), wantStatus)
			preserved, err := rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, policy.TemplateKey)
			if err != nil || preserved.TransitionOperationID == nil || *preserved.TransitionOperationID != op.ID || preserved.Version != reserved.ExpectedVersion {
				t.Fatalf("profile request rewrote an unrelated transition: %+v %v", preserved, err)
			}
		})
	}
}
