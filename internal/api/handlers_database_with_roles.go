package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

var basicDatabaseNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,59}$`)
var basicDatabaseOwnerRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

type createDatabaseWithRolesRequest struct {
	createResourceRequest
	CreateDefaultRoles     bool      `json:"create_default_roles"`
	RequestID              uuid.UUID `json:"request_id"`
	UpdatedAt              time.Time `json:"updated_at"`
	ExpectedTargetIdentity string    `json:"expected_target_identity"`
}

func (r *createDatabaseWithRolesRequest) validate() error {
	if err := r.createResourceRequest.validate(); err != nil {
		return err
	}
	if !r.CreateDefaultRoles || r.RequestID == uuid.Nil || r.UpdatedAt.IsZero() || r.ExpectedTargetIdentity == "" {
		return errors.New("create_default_roles=true, request_id, updated_at and expected_target_identity are required")
	}
	if !basicDatabaseNameRE.MatchString(r.Name) {
		return errors.New("database name for default roles must be a portable identifier of at most 60 bytes")
	}
	r.Owner = strings.TrimSpace(r.Owner)
	if !basicDatabaseOwnerRE.MatchString(r.Owner) {
		return errors.New("an explicit database owner is required for default roles; use a portable identifier of at most 63 bytes")
	}
	return nil
}

// This distinct endpoint is intentional: an old API ignores unknown JSON
// fields on /resources. A checked request must fail with 404 on that API, not
// silently create only the database while dropping the requested role intent.
func (s *Server) createDatabaseWithRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req createDatabaseWithRolesRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, connectionID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err := s.connections.Get(ctx, tx, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if conn.Engine != "postgres" {
		respondError(w, http.StatusConflict, "database creation with default roles requires PostgreSQL")
		return
	}
	key := fmt.Sprintf("postgres-database-with-roles-v2:%s:%s", conn.ID, req.RequestID)
	// A lost response replays the immutable accepted intent even if a later
	// discovery changed updated_at or authority. This is a read-only receipt,
	// not permission to execute the old intent on a new target.
	if previous, err := s.operations.GetByIdempotencyKey(ctx, tx, key); err == nil {
		var payload jobs.DatabaseCreateWithRolesPayload
		if json.Unmarshal(previous.Payload, &payload) != nil || previous.Kind != jobs.KindPostgresDatabaseCreateWithRolesV2 ||
			payload.Name != req.Name || payload.ExpectedTargetIdentity != req.ExpectedTargetIdentity ||
			payload.ExpectedDatabaseOwner != req.Owner || !sameDatabaseOptionsV2(payload.Options, req.options()) {
			respondError(w, http.StatusConflict, "request_id was already used for another database intent")
			return
		}
		respondJSON(w, http.StatusAccepted, map[string]any{
			"resource_id": payload.ResourceID, "operation_id": previous.ID,
			"create_default_roles": true, "deduplicated": true,
		})
		return
	} else if !errors.Is(err, operations.ErrNotFound) {
		respondStoreError(ctx, w, err)
		return
	}
	pins, err := requirePostgresProvisioningAuthority(conn,
		adapter.ResourceCapability("create", resourceKindDatabase), adapter.CapRolePolicyCreate)
	if err != nil || pins.TargetIdentity != req.ExpectedTargetIdentity || !conn.UpdatedAt.Equal(req.UpdatedAt) {
		respondError(w, http.StatusConflict, "PostgreSQL provisioning preview is stale; refresh discovery")
		return
	}
	owner, err := s.inventory.FindAccountByIdentity(ctx, tx, conn.ID, req.Owner)
	if err != nil || owner.Status != inventory.AccountActive {
		respondError(w, http.StatusConflict, "database owner must be an observed active PostgreSQL role")
		return
	}
	var ownerAttrs map[string]any
	if json.Unmarshal(owner.Attributes, &ownerAttrs) != nil {
		respondError(w, http.StatusConflict, "database owner identity is not current")
		return
	}
	if adapter.AttrBool(ownerAttrs, "superuser") {
		respondError(w, http.StatusConflict, "database owner must not be a PostgreSQL SUPERUSER")
		return
	}
	ownerOID, ok := uint32JSON(ownerAttrs["role_oid"])
	if !ok {
		respondError(w, http.StatusConflict, "database owner role incarnation is unavailable; run discovery")
		return
	}
	if err := checkDatabaseRoleCatalogV2(conn, req.Name); err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	resource, err := s.inventory.CreatePlannedResource(ctx, tx, inventory.CreatePlannedResourceParams{
		ConnectionID: conn.ID, Kind: resourceKindDatabase, ExternalID: "db:" + req.Name,
		Name: req.Name, CanonicalPath: req.Name,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	payload, err := json.Marshal(jobs.DatabaseCreateWithRolesPayload{
		ResourceID: resource.ID, Name: req.Name, Options: req.options(),
		ExpectedTargetIdentity: pins.TargetIdentity, ExpectedAdminIdentity: pins.AdminIdentity,
		ExpectedConfigIncarnation:     pins.ConfigIncarnation,
		ExpectedCredentialIncarnation: pins.CredentialIncarnation,
		ExpectedDatabaseOwner:         req.Owner, ExpectedDatabaseOwnerOID: ownerOID,
		ExpectedCatalogFingerprint: pins.CatalogFingerprint,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindPostgresDatabaseCreateWithRolesV2, IdempotencyKey: &key,
		ConnectionID: &conn.ID, ResourceID: &resource.ID, Payload: payload,
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), CorrelationID: req.RequestID.String(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := databaseprovisioning.NewStore().Create(ctx, tx, op.ID, resource.ID, conn.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "database.provisioning_requested",
		ConnectionID: &conn.ID, ResourceID: &resource.ID, OperationID: &op.ID, Result: audit.ResultSuccess,
	}, map[string]any{"database": req.Name, "owner": req.Owner, "read_role": "r_" + req.Name,
		"read_write_role": "rw_" + req.Name}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"resource_id": resource.ID, "operation_id": op.ID, "create_default_roles": true,
	})
}

func checkDatabaseRoleCatalogV2(conn connections.Connection, name string) error {
	templates, err := postgresconfig.FromAttributes(connectionDiscoveryAttributes(conn))
	if err != nil {
		return err
	}
	if len(templates)+2 > postgresconfig.MaxTemplates {
		return errors.New("the role-policy catalog has no room for two default roles")
	}
	for _, template := range templates {
		if template.RoleName == "r_"+name || template.RoleName == "rw_"+name {
			return errors.New("a default role already exists in the catalog")
		}
	}
	return nil
}

func uint32JSON(value any) (uint32, bool) {
	switch value := value.(type) {
	case float64:
		return uint32(value), value > 0 && value <= float64(^uint32(0)) && value == float64(uint32(value))
	case uint32:
		return value, value > 0
	case int:
		return uint32(value), value > 0
	default:
		return 0, false
	}
}

func sameDatabaseOptionsV2(left, right map[string]any) bool {
	a, err := json.Marshal(left)
	if err != nil {
		return false
	}
	b, err := json.Marshal(right)
	return err == nil && rawJSONEqual(a, b)
}

type databaseProvisioningJSON struct {
	Phase            string `json:"phase"`
	DatabaseName     string `json:"database_name"`
	ReadRole         string `json:"read_role"`
	ReadWriteRole    string `json:"read_write_role"`
	DatabaseCreated  bool   `json:"database_created"`
	ReadCreated      bool   `json:"read_created"`
	ReadWriteCreated bool   `json:"read_write_created"`
	ErrorCode        string `json:"error_code,omitempty"`
}

// decorateLegacyDatabaseProvisioning keeps the durable journal visible. A v2
// root is retryable unless CREATE may have reached PostgreSQL without a durable
// receipt; legacy roots stay history-only.
func (s *Server) decorateLegacyDatabaseProvisioning(ctx context.Context, out *operationJSON,
	op operations.Operation,
) error {
	retryable := false
	out.Retryable = &retryable
	row, err := databaseprovisioning.NewStore().Get(ctx, s.pool, op.ID)
	if errors.Is(err, databaseprovisioning.ErrNotFound) && op.ConnectionID == nil {
		// Connection deletion removes the workflow journal but deliberately
		// leaves operation history readable.
		return nil
	}
	if err != nil {
		return err
	}
	retryable = op.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 &&
		op.Status == operations.StatusFailed && (!row.DatabaseCreateStarted || row.DatabaseCreated)
	out.Retryable = &retryable
	var payload jobs.DatabaseCreateWithRolesPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		return fmt.Errorf("decode historical database provisioning payload: %w", err)
	}
	out.DatabaseProvisioning = &databaseProvisioningJSON{
		Phase:            row.Phase,
		DatabaseName:     payload.Name,
		ReadRole:         "r_" + payload.Name,
		ReadWriteRole:    "rw_" + payload.Name,
		DatabaseCreated:  row.DatabaseCreated,
		ReadCreated:      row.ReadCreated,
		ReadWriteCreated: row.ReadWriteCreated,
		ErrorCode:        row.ErrorCode,
	}
	return nil
}
