package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// auditActionBindingAdopted — audit action принятия unmanaged binding
// под управление.
const auditActionBindingAdopted = "binding.adopted"

// driftKindConnectionDegraded — finding уровня connection: целевая
// система недоступна или discovery на ней падает, данные дрифта могли
// устареть. Остальные виды приходят из inventory.DriftFindings.
const driftKindConnectionDegraded = "connection_degraded"

// isDegradedConnectionStatus сообщает, попадает ли статус connection в
// отчёт дрифта как connection_degraded. Чистая функция для юнит-тестов.
func isDegradedConnectionStatus(status connections.Status) bool {
	switch status {
	case connections.StatusDegraded, connections.StatusConnectionFailed, connections.StatusDiscoveryFailed:
		return true
	default:
		return false
	}
}

// driftFindingJSON — одно расхождение в ответе GET /api/v1/drift.
// Ссылочные id заполняются по виду finding (см. inventory.DriftFinding);
// для connection_degraded задан только connection_id.
type driftFindingJSON struct {
	Kind            string     `json:"kind"`
	ConnectionID    uuid.UUID  `json:"connection_id"`
	BindingID       *uuid.UUID `json:"binding_id,omitempty"`
	AccountID       *uuid.UUID `json:"account_id,omitempty"`
	ResourceID      *uuid.UUID `json:"resource_id,omitempty"`
	PermissionID    *uuid.UUID `json:"permission_id,omitempty"`
	AccountIdentity string     `json:"account_identity,omitempty"`
	PermissionName  string     `json:"permission_name,omitempty"`
	ResourceName    string     `json:"resource_name,omitempty"`
	Detail          string     `json:"detail"`
}

// driftCountsJSON — сводка находок отчёта по видам.
type driftCountsJSON struct {
	BindingDrift        int `json:"binding_drift"`
	UnmanagedBinding    int `json:"unmanaged_binding"`
	MissingResource     int `json:"missing_resource"`
	MissingAccount      int `json:"missing_account"`
	DegradedConnections int `json:"degraded_connections"`
}

// driftBaselinedJSON — находка, принятая как ожидаемая: сама находка плюс
// кто, когда и почему принял.
type driftBaselinedJSON struct {
	driftFindingJSON
	BaselineID uuid.UUID `json:"baseline_id"`
	Reason     string    `json:"reason,omitempty"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// driftResponse — тело ответа GET /api/v1/drift. Baselined-находки не
// смешиваются с активными: активный список — сигнал, baseline — признанный
// фон, который остаётся видимым и обратимым.
type driftResponse struct {
	Findings  []driftFindingJSON   `json:"findings"`
	Baselined []driftBaselinedJSON `json:"baselined"`
	Counts    driftCountsJSON      `json:"counts"`
}

// findingBaselineRef возвращает id объекта находки, которым она адресуется
// в baseline; nil — вид не поддерживает baseline. Чистая функция.
func findingBaselineRef(f driftFindingJSON) *uuid.UUID {
	switch f.Kind {
	case inventory.DriftKindBindingDrift, inventory.DriftKindUnmanagedBinding:
		return f.BindingID
	case inventory.DriftKindMissingResource:
		return f.ResourceID
	case inventory.DriftKindMissingAccount:
		return f.AccountID
	default:
		return nil
	}
}

// splitBaselinedFindings делит находки на активные и принятые как
// ожидаемые. Baseline без живой находки (объект исчез или починился) не
// показывается вовсе: ему нечего скрывать. Чистая функция для юнит-тестов.
func splitBaselinedFindings(findings []driftFindingJSON, baselines []inventory.DriftBaseline) ([]driftFindingJSON, []driftBaselinedJSON) {
	byRef := make(map[string]inventory.DriftBaseline, len(baselines))
	for _, b := range baselines {
		byRef[b.Kind+" "+b.RefID.String()] = b
	}
	active := make([]driftFindingJSON, 0, len(findings))
	baselined := make([]driftBaselinedJSON, 0)
	for _, f := range findings {
		ref := findingBaselineRef(f)
		if ref == nil {
			active = append(active, f)
			continue
		}
		b, ok := byRef[f.Kind+" "+ref.String()]
		if !ok {
			active = append(active, f)
			continue
		}
		baselined = append(baselined, driftBaselinedJSON{
			driftFindingJSON: f,
			BaselineID:       b.ID,
			Reason:           b.Reason,
			CreatedBy:        b.CreatedBy,
			CreatedAt:        b.CreatedAt,
		})
	}
	return active, baselined
}

// driftCounts считает сводку по видам находок; неизвестные виды
// игнорируются. Чистая функция для юнит-тестов.
func driftCounts(findings []driftFindingJSON) driftCountsJSON {
	var c driftCountsJSON
	for i := range findings {
		switch findings[i].Kind {
		case inventory.DriftKindBindingDrift:
			c.BindingDrift++
		case inventory.DriftKindUnmanagedBinding:
			c.UnmanagedBinding++
		case inventory.DriftKindMissingResource:
			c.MissingResource++
		case inventory.DriftKindMissingAccount:
			c.MissingAccount++
		case driftKindConnectionDegraded:
			c.DegradedConnections++
		}
	}
	return c
}

// toDriftFindingJSON собирает driftFindingJSON из доменной модели.
func toDriftFindingJSON(f inventory.DriftFinding) driftFindingJSON {
	return driftFindingJSON{
		Kind:            f.Kind,
		ConnectionID:    f.ConnectionID,
		BindingID:       f.BindingID,
		AccountID:       f.AccountID,
		ResourceID:      f.ResourceID,
		PermissionID:    f.PermissionID,
		AccountIdentity: f.AccountIdentity,
		PermissionName:  f.PermissionName,
		ResourceName:    f.ResourceName,
		Detail:          f.Detail,
	}
}

// listDrift — GET /api/v1/drift?connection_id= (viewer): отчёт о
// расхождениях для раздела «Дрифт». Findings уровня connection
// (degraded/connection_failed/discovery_failed) идут первыми — они
// объясняют возможное устаревание остальных данных, затем findings
// инвентаря в порядке inventory.DriftFindings. Counts — сводка по видам.
func (s *Server) listDrift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, err := queryUUID(r, "connection_id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	// При фильтре несуществующий connection — 404, как у вложенных
	// списков инвентаря.
	var conns []connections.Connection
	if connectionID != nil {
		conn, err := s.connections.Get(ctx, s.pool, *connectionID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if scopeErr := s.checkConnectionScope(ctx, sess, conn.Environment); scopeErr != nil {
			s.respondScopeError(ctx, w, scopeErr)
			return
		}
		conns = []connections.Connection{conn}
	} else {
		conns, err = s.connections.List(ctx, s.pool)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		conns, err = s.filterConnectionsByScope(ctx, sess, conns)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	visible := make(map[uuid.UUID]bool, len(conns))
	for i := range conns {
		visible[conns[i].ID] = true
	}

	findings := make([]driftFindingJSON, 0, len(conns))
	for i := range conns {
		c := &conns[i]
		if !isDegradedConnectionStatus(c.Status) {
			continue
		}
		findings = append(findings, driftFindingJSON{
			Kind:         driftKindConnectionDegraded,
			ConnectionID: c.ID,
			Detail:       fmt.Sprintf("подключение %q в статусе %q", c.DisplayName, c.Status),
		})
	}

	inventoryFindings, err := s.inventory.DriftFindings(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	for i := range inventoryFindings {
		if !visible[inventoryFindings[i].ConnectionID] {
			continue
		}
		findings = append(findings, toDriftFindingJSON(inventoryFindings[i]))
	}

	baselines, err := s.inventory.ListDriftBaselines(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	active, baselined := splitBaselinedFindings(findings, baselines)
	// Counts считаются по активным находкам: baseline и существует ради
	// того, чтобы признанный фон не поднимал счётчики дрифта.
	respondJSON(w, http.StatusOK, driftResponse{
		Findings:  active,
		Baselined: baselined,
		Counts:    driftCounts(active),
	})
}

// auditActionDriftBaselined / ...Removed — audit-действия baseline находок.
const (
	auditActionDriftBaselined       = "drift.baselined"
	auditActionDriftBaselineRemoved = "drift.baseline_removed"
)

// driftBaselineRequest — тело POST /api/v1/drift/baselines.
type driftBaselineRequest struct {
	Kind         string    `json:"kind"`
	RefID        uuid.UUID `json:"ref_id"`
	ConnectionID uuid.UUID `json:"connection_id"`
	Reason       string    `json:"reason"`
}

// createDriftBaseline — POST /api/v1/drift/baselines (operator): принять
// находку как ожидаемую. Целевые системы не меняются — решение живёт в
// metadata и обратимо удалением baseline. Повторное принятие идемпотентно.
func (s *Server) createDriftBaseline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req driftBaselineRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !inventory.BaselineableDriftKind(req.Kind) {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("drift kind %q cannot be baselined", req.Kind))
		return
	}
	if req.RefID == uuid.Nil || req.ConnectionID == uuid.Nil {
		respondError(w, http.StatusBadRequest, "ref_id and connection_id are required")
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, req.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope: признавать дрифт своим фоном можно только в своих окружениях.
	if err := s.checkConnectionScope(ctx, sess, environmentOf(conn)); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	baseline, err := s.inventory.CreateDriftBaseline(ctx, tx, inventory.DriftBaseline{
		Kind:         req.Kind,
		RefID:        req.RefID,
		ConnectionID: req.ConnectionID,
		Reason:       strings.TrimSpace(req.Reason),
		CreatedBy:    sess.ActorID(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionDriftBaselined,
		ConnectionID: &req.ConnectionID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"baseline_id": baseline.ID,
		"kind":        baseline.Kind,
		"ref_id":      baseline.RefID,
		"reason":      baseline.Reason,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit drift baseline: %w", err))
		return
	}
	respondJSON(w, http.StatusCreated, map[string]any{
		"baseline_id":   baseline.ID,
		"kind":          baseline.Kind,
		"ref_id":        baseline.RefID,
		"connection_id": baseline.ConnectionID,
	})
}

// deleteDriftBaseline — DELETE /api/v1/drift/baselines/{id} (operator):
// вернуть находку в активный дрифт.
func (s *Server) deleteDriftBaseline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
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

	baseline, err := s.inventory.DeleteDriftBaseline(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err := s.connections.Get(ctx, tx, baseline.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope после удаления безопасен: транзакция ещё не закоммичена.
	if err := s.checkConnectionScope(ctx, sess, environmentOf(conn)); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionDriftBaselineRemoved,
		ConnectionID: &baseline.ConnectionID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"baseline_id": baseline.ID,
		"kind":        baseline.Kind,
		"ref_id":      baseline.RefID,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit drift baseline removal: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"baseline_id": baseline.ID, "removed": true})
}

// adoptBinding — POST /api/v1/bindings/{id}/adopt (operator): принимает
// unmanaged binding под управление (desired present). Операция в worker
// не ставится: доступ уже существует в целевой системе, меняется только
// desired state в metadata, поэтому ответ — 200 с обновлённым binding.
// Уже managed binding — 409.
func (s *Server) adoptBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
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

	binding, err := s.inventory.AdoptBinding(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	acct, err := s.inventory.GetAccount(ctx, tx, binding.AccountID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID)) {
		return
	}
	perm, err := s.inventory.GetPermission(ctx, tx, binding.PermissionDefinitionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Унаследованное право под управление не принимается: grantor взял бы на
	// себя обязательство, которое исполнить не может — прямого ребра в
	// целевой системе нет, и отзыв такого binding был бы no-op. Проверка
	// после AdoptBinding безопасна: транзакция ещё не закоммичена, откат
	// вернёт desired_state в NULL.
	if binding.Source == string(inventory.BindingSourceInherited) {
		respondError(w, http.StatusConflict,
			"permission is inherited through a role and cannot be managed directly: "+
				"manage the role that grants it")
		return
	}
	// Adopt dangerous-права — только admin (симметрично dangerousGrantCheck):
	// принятие под управление легитимизирует внешний опасный грант. Проверка
	// после AdoptBinding безопасна — транзакция ещё не закоммичена.
	if perm.Dangerous && !sess.Role.Allows(auth.RoleAdmin) {
		respondError(w, http.StatusForbidden, "adopting a dangerous permission requires admin role")
		return
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionBindingAdopted,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"binding_id":      binding.ID,
		"engine_identity": acct.EngineIdentity,
		"permission":      perm.ExternalID,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit adopt binding: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, toBindingJSON(binding))
}
