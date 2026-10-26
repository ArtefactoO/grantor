// Создание ролей-контейнеров подключения: POST /api/v1/connections/{id}/roles.
//
// Роль без логина (PostgreSQL NOLOGIN) не аутентифицируется и пароля не имеет
// — Vault здесь не участвует вовсе. Смысл её существования в том, что после
// следующего discovery она видна и как учётная запись kind=group, и как
// назначаемое право role:<имя>, которое выдаётся обычным грантом.
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
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

const auditActionRoleCreateRequested = "role.create_requested"

// maxRoleNameBytes — предел длины имени роли. PostgreSQL молча обрезает
// идентификаторы длиннее NAMEDATALEN-1, и обрезанное имя разошлось бы с тем,
// что grantor записал себе.
const maxRoleNameBytes = 63

// createRoleRequest — тело POST /api/v1/connections/{id}/roles.
type createRoleRequest struct {
	Name string `json:"name"`
}

func (req *createRoleRequest) validate() error {
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
	return nil
}

// createRole заводит роль-контейнер в целевой системе. PostgreSQL bare-role
// scaffold — admin-only; operator там назначает только готовые managed роли.
//
// Строка accounts создаётся сразу в статусе provisioning — тем же приёмом, что
// account.create: она резервирует identity в пределах подключения (повторный
// запрос получает 409 вместо второй операции) и не участвует в массовых
// действиях, пока применение не подтверждено. Credential не создаётся: у роли
// без логина его нет.
func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req createRoleRequest
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
	if roleCreationRequiresAdmin(conn.Engine) && !sess.Role.Allows(auth.RoleAdmin) {
		respondError(w, http.StatusForbidden,
			"creating bare database roles requires admin; operators may only assign managed roles")
		return
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"connection status %q does not allow role provisioning; discover the connection first", conn.Status))
		return
	}
	if conn.Engine == "postgres" {
		if _, err := requirePostgresProvisioningAuthority(conn, adapter.CapRoleCreate); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}
	// Два независимых слоя: манифест движка и эффективный набор подключения
	// (он же сужается ConnectionCapabilityScoper по наблюдённой топологии).
	if !engineSupports(conn.Engine, adapter.CapRoleCreate) ||
		!slices.Contains(conn.Capabilities, string(adapter.CapRoleCreate)) {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"%s is unsupported for engine %q of connection %s",
			adapter.CapRoleCreate, conn.Engine, conn.ID))
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: begin create role: %w", err))
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
	var postgresPins postgresProvisioningPins
	if conn.Engine == "postgres" {
		postgresPins, err = requirePostgresProvisioningAuthority(conn, adapter.CapRoleCreate)
		if err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}

	acct, err := s.inventory.CreateProvisioningAccount(ctx, tx, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: req.Name,
		Kind:           inventory.AccountKindGroup,
	})
	if err != nil {
		if errors.Is(err, inventory.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"identity %q already exists in this connection", req.Name))
			return
		}
		respondStoreError(ctx, w, err)
		return
	}
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, acct.Status)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, ExpectedStatus: acct.Status,
		ExpectedLifecycleVersion:      reserved.LifecycleVersion,
		ExpectedAdminIdentity:         postgresPins.AdminIdentity,
		ExpectedTargetIdentity:        postgresPins.TargetIdentity,
		ExpectedConfigIncarnation:     postgresPins.ConfigIncarnation,
		ExpectedCredentialIncarnation: postgresPins.CredentialIncarnation,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
		return
	}
	operationKind := jobs.KindRoleCreate
	if conn.Engine == "postgres" {
		operationKind = jobs.KindPostgresRoleCreateV2
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          operationKind,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
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
		Action:       auditActionRoleCreateRequested,
		ConnectionID: &conn.ID,
		AccountID:    &acct.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{"role": acct.EngineIdentity}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create role: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id":   acct.ID,
		"operation_id": op.ID,
	})
}

func roleCreationRequiresAdmin(engine string) bool {
	return engine == "postgres" || engine == "mongodb"
}
