// Создание ресурсов подключения: POST /api/v1/connections/{id}/resources.
//
// Сейчас поддерживается единственный вид — database (architecture §11.2).
// Операция admin-only и без автоматического отката: DROP DATABASE не
// выполняется никогда, поэтому провалившееся создание оставляет planned-строку
// инвентаря, видимую оператору.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

const auditActionResourceCreateRequested = "resource.create_requested"

// resourceKindDatabase — единственный поддерживаемый вид создаваемого ресурса.
const resourceKindDatabase = "database"

// createResourceRequest — тело POST /api/v1/connections/{id}/resources.
// Опции соответствуют architecture §11.2; допустимость template, tablespace и
// owner проверяет adapter по allowlists подключения.
type createResourceRequest struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Owner           string `json:"owner"`
	Template        string `json:"template"`
	Encoding        string `json:"encoding"`
	Locale          string `json:"locale"`
	Tablespace      string `json:"tablespace"`
	ConnectionLimit *int   `json:"connection_limit"`
}

func (req *createResourceRequest) validate() error {
	if req.Kind == "" {
		req.Kind = resourceKindDatabase
	}
	if req.Kind != resourceKindDatabase {
		return fmt.Errorf("kind %q is not supported; only %q can be created",
			req.Kind, resourceKindDatabase)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > maxRoleNameBytes {
		return fmt.Errorf("name must be at most %d bytes", maxRoleNameBytes)
	}
	if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("name must not contain control characters")
	}
	if strings.ContainsAny(name, " \t\n\r") {
		return errors.New("name must not contain whitespace")
	}
	req.Name = name
	if req.ConnectionLimit != nil && *req.ConnectionLimit < -1 {
		return errors.New("connection_limit must be -1 or greater")
	}
	return nil
}

// options собирает непустые опции создания в форму, которую понимает adapter.
func (req *createResourceRequest) options() map[string]any {
	out := map[string]any{}
	for key, value := range map[string]string{
		"owner": req.Owner, "template": req.Template,
		"encoding": req.Encoding, "locale": req.Locale, "tablespace": req.Tablespace,
	} {
		if strings.TrimSpace(value) != "" {
			out[key] = strings.TrimSpace(value)
		}
	}
	if req.ConnectionLimit != nil {
		out["connection_limit"] = *req.ConnectionLimit
	}
	return out
}

// createResource заводит ресурс в целевой системе (admin).
//
// Строка инвентаря создаётся в статусе planned до постановки операции: она
// резервирует (kind, external_id) подключения, поэтому повторный запрос
// получает 409 вместо второй операции создания.
func (s *Server) createResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req createResourceRequest
	if !decodeJSON(w, r, &req) {
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

	conn, err := s.connections.Get(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"connection status %q does not allow resource provisioning; discover the connection first", conn.Status))
		return
	}
	capability := adapter.ResourceCapability("create", req.Kind)
	if conn.Engine == "postgres" {
		if _, err := requirePostgresProvisioningAuthority(conn, capability); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		if strings.TrimSpace(req.Owner) == "" {
			respondError(w, http.StatusBadRequest, "owner is required for PostgreSQL database creation")
			return
		}
	}
	if !engineSupports(conn.Engine, capability) ||
		!slices.Contains(conn.Capabilities, string(capability)) {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"%s is unsupported for engine %q of connection %s", capability, conn.Engine, conn.ID))
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: begin create resource: %w", err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, conn.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err = s.connections.Get(ctx, tx, conn.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var (
		postgresPins postgresProvisioningPins
		ownerOID     uint32
	)
	if conn.Engine == "postgres" {
		postgresPins, err = requirePostgresProvisioningAuthority(conn, capability)
		if err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		owner, findErr := s.inventory.FindAccountByIdentity(ctx, tx, conn.ID, strings.TrimSpace(req.Owner))
		if findErr != nil || owner.Status != inventory.AccountActive {
			respondError(w, http.StatusConflict, "database owner must be an observed active PostgreSQL role")
			return
		}
		ownerAttributes := decodeAttributes(owner.Attributes)
		if adapter.AttrBool(ownerAttributes, "superuser") {
			respondError(w, http.StatusConflict, "database owner must not be a PostgreSQL SUPERUSER")
			return
		}
		var ok bool
		ownerOID, ok = uint32JSON(ownerAttributes["role_oid"])
		if !ok {
			respondError(w, http.StatusConflict, "database owner role incarnation is unavailable; run discovery")
			return
		}
	}

	// External id совпадает с тем, что построит discovery: иначе следующий
	// снимок завёл бы вторую строку того же объекта.
	res, err := s.inventory.CreatePlannedResource(ctx, tx, inventory.CreatePlannedResourceParams{
		ConnectionID:  conn.ID,
		Kind:          req.Kind,
		ExternalID:    "db:" + req.Name,
		Name:          req.Name,
		CanonicalPath: req.Name,
	})
	if err != nil {
		if errors.Is(err, inventory.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"%s %q already exists in this connection", req.Kind, req.Name))
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	payload, err := json.Marshal(jobs.ResourcePayload{
		ResourceID: res.ID, Kind: req.Kind, Name: req.Name, Options: req.options(),
		ExpectedTargetIdentity:        postgresPins.TargetIdentity,
		ExpectedAdminIdentity:         postgresPins.AdminIdentity,
		ExpectedConfigIncarnation:     postgresPins.ConfigIncarnation,
		ExpectedCredentialIncarnation: postgresPins.CredentialIncarnation,
		ExpectedDatabaseOwner:         strings.TrimSpace(req.Owner), ExpectedDatabaseOwnerOID: ownerOID,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal resource payload: %w", err))
		return
	}
	operationKind := jobs.KindResourceCreateDatabase
	if conn.Engine == "postgres" {
		operationKind = jobs.KindPostgresResourceCreateDatabaseV2
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          operationKind,
		ConnectionID:  &conn.ID,
		ResourceID:    &res.ID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionResourceCreateRequested,
		ConnectionID: &conn.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{"kind": req.Kind, "name": req.Name}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create resource: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"resource_id":  res.ID,
		"operation_id": op.ID,
	})
}
