//go:build integration

package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

func TestIntegrationOffboardUnownedPasswordAccountDoesNotRequireRotation(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		label := "skip_unowned"
		if takeover {
			label = "explicit_takeover_requires_capability"
		}
		t.Run(label, func(t *testing.T) {
			ctx := t.Context()
			client := newTestVault(t)
			env := newTestEnv(t, client)
			admin := session(auth.RoleAdmin)
			conn := createKafkaPatchConnection(t, env, `{"acl_authorizer":"enabled"}`)
			var err error
			conn, err = connections.NewStore().Update(ctx, env.pool, conn.ID, connections.UpdateParams{DisplayName: conn.DisplayName, Environment: conn.Environment, Tags: conn.Tags, Endpoints: conn.Endpoints, TLSConfig: conn.TLSConfig, DiscoveryConfig: json.RawMessage(`{"sasl_mechanism":"plain","security_protocol":"sasl_plaintext"}`), Capabilities: conn.Capabilities})
			if err != nil {
				t.Fatal(err)
			}
			caps := connections.EffectiveCapabilities(conn, conn.Capabilities)
			if conn.AuthMode != "password" || slices.Contains(caps, string(adapter.CapCredentialRotate)) || !slices.Contains(caps, string(adapter.CapAccessRevoke)) {
				t.Fatalf("fixture must support access without credential rotation: %v", caps)
			}
			principal := createPrincipalRow(t, env.pool, "unowned-plain-"+uuid.NewString())
			acct, err := inventory.NewStore().CreateManagedAccount(ctx, env.pool, inventory.CreateManagedAccountParams{ConnectionID: conn.ID, PrincipalID: &principal.ID, EngineIdentity: "externally_owned_" + uuid.NewString()})
			if err != nil {
				t.Fatal(err)
			}
			secretPath, _ := vault.AccountCredentialPath(acct.ID.String())
			if _, err = client.Metadata(ctx, secretPath); !errors.Is(err, vault.ErrNotFound) {
				t.Fatalf("fixture unexpectedly owns a credential: %v", err)
			}
			resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/offboard", map[string]any{"confirm": true, "takeover_credentials": takeover}, &admin, true)
			if takeover {
				requireStatus(t, resp, http.StatusConflict)
				var count int
				if err = env.pool.QueryRow(ctx, `select count(*) from operations where principal_id=$1`, principal.ID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("unsupported takeover reserved operations: %d %v", count, err)
				}
				after, err := inventory.NewStore().GetAccount(ctx, env.pool, acct.ID)
				if err != nil || after.LifecycleVersion != acct.LifecycleVersion {
					t.Fatalf("unsupported takeover changed lifecycle: %+v %v", after, err)
				}
			} else {
				requireStatus(t, resp, http.StatusAccepted)
				var out offboardResponse
				if err = json.Unmarshal(readBody(t, resp), &out); err != nil {
					t.Fatal(err)
				}
				if len(out.Children) != 0 || len(out.CredentialTakeoverRequired) != 1 || out.CredentialTakeoverRequired[0].EngineIdentity != acct.EngineIdentity {
					t.Fatalf("unowned account was not explicitly skipped: %+v", out)
				}
				requireOperation(t, env, out.OperationID, jobs.KindBulkPrincipalOffboard, operations.StatusSuccess, nil)
			}
			if _, err = client.Metadata(ctx, secretPath); !errors.Is(err, vault.ErrNotFound) {
				t.Fatalf("offboard wrote a password for an unowned account: %v", err)
			}
		})
	}
}
