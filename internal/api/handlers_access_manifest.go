package api

// Декларативный access manifest (ADR-0009): plan (dry-run diff), apply
// (массовые grant/revoke/create) и export текущего managed-состояния.
//
// Оркестрация не дублируется: apply переиспользует те же store-методы и
// operation kinds, что и principal-centric выдача и одиночный grant/revoke
// (ensurePrincipalEnvCredential + ensurePrincipalAccount + enqueueAccountProvision
// для create; createGrant для grant; SetBindingDesired absent + KindAccessRevoke
// для revoke). Diff-логика живёт в core/accessmanifest и на apply не
// переписывается: apply идёт по действиям пересчитанного на сервере плана.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/accessmanifest"
	"github.com/ArtefactoO/grantor/internal/core/approval"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// auditActionManifestApplied — audit-действие применения манифеста.
const auditActionManifestApplied = "access.manifest_applied"

// manifestPlanner собирает Planner из сторов сервера.
func (s *Server) manifestPlanner() accessmanifest.Planner {
	return accessmanifest.Planner{
		Connections: s.connections,
		Principals:  s.principals,
		Inventory:   s.inventory,
	}
}

// manifestApplyRequest — тело POST /api/v1/access/apply: манифест (с prune)
// плюс confirm для dangerous-действий. Manifest встроен, поэтому его поля
// (version/environment/prune/entries) поднимаются на верхний уровень и в
// JSON, и в YAML (yaml:",inline" — явный аналог JSON-встраивания).
type manifestApplyRequest struct {
	accessmanifest.Manifest `yaml:",inline"`

	Confirm bool `json:"confirm" yaml:"confirm"`
}

// Media types тела манифеста. JSON — формат по умолчанию; YAML принимается
// по явному Content-Type (application/yaml или text/yaml).
const (
	mediaTypeJSON     = "application/json"
	mediaTypeYAML     = "application/yaml"
	mediaTypeYAMLText = "text/yaml"
)

// manifestContentTypesHint — подсказка допустимых Content-Type в ошибках 415.
const manifestContentTypesHint = "use application/json, application/yaml or text/yaml"

// decodeManifestBody читает тело запроса манифеста как JSON (пустой или
// application/json Content-Type — поведение по умолчанию, как decodeJSON) или
// YAML (application/yaml, text/yaml). Оба формата декодируются в одни и те же
// структуры: валидация и diff-логика не форкаются. Неизвестный или
// нечитаемый Content-Type — 415; лимит размера тела единый (maxRequestBody).
func decodeManifestBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType := ""
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil {
			respondError(w, http.StatusUnsupportedMediaType,
				"malformed Content-Type; "+manifestContentTypesHint)
			return false
		}
		mediaType = mt
	}
	switch mediaType {
	case "", mediaTypeJSON:
		return decodeJSON(w, r, dst)
	case mediaTypeYAML, mediaTypeYAMLText:
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		if err := yaml.NewDecoder(r.Body).Decode(dst); err != nil {
			respondError(w, http.StatusBadRequest, "invalid YAML body")
			return false
		}
		return true
	default:
		respondError(w, http.StatusUnsupportedMediaType,
			fmt.Sprintf("unsupported Content-Type %q; %s", mediaType, manifestContentTypesHint))
		return false
	}
}

// manifestSummary — сводка плана для ответа.
type manifestSummary struct {
	Grants    int `json:"grants"`
	Revokes   int `json:"revokes"`
	Replaces  int `json:"replaces"`
	Creates   int `json:"creates"`
	Dangerous int `json:"dangerous"`
}

// summarizePlan считает сводку по действиям плана.
func summarizePlan(plan accessmanifest.Plan) manifestSummary {
	var sum manifestSummary
	for i := range plan.Actions {
		switch plan.Actions[i].Kind {
		case accessmanifest.ActionGrant:
			sum.Grants++
		case accessmanifest.ActionRevoke:
			sum.Revokes++
		case accessmanifest.ActionReplace:
			sum.Replaces++
		case accessmanifest.ActionCreateAccount:
			sum.Creates++
		}
		if plan.Actions[i].Dangerous {
			sum.Dangerous++
		}
	}
	return sum
}

// checkManifestScope проверяет scope operator по каждому затронутому
// действиями плана окружению (дедупликация по окружению). Пишет 403 и
// возвращает false при нарушении. Для admin/viewer/disabled — no-op.
func (s *Server) checkManifestScope(w http.ResponseWriter, r *http.Request, sess auth.Session, plan accessmanifest.Plan) bool {
	ctx := r.Context()
	if !s.scopeApplies(sess) {
		return true
	}
	seen := map[string]bool{}
	for i := range plan.Actions {
		env := plan.Actions[i].Resolved.Environment
		if seen[env] {
			continue
		}
		seen[env] = true
		if err := s.checkConnectionScope(ctx, sess, env); err != nil {
			s.respondScopeError(ctx, w, err)
			return false
		}
	}
	return true
}

// resolveManifestConnectionScope резолвит optional query `connection` по UUID
// или display_name и применяет к нему обычный operator scope до plan. uuid.Nil
// сохраняет прежнюю глобальную семантику клиентов без query-параметра.
func (s *Server) resolveManifestConnectionScope(w http.ResponseWriter, r *http.Request, sess auth.Session) (uuid.UUID, bool) {
	ref := r.URL.Query().Get("connection")
	if ref == "" {
		return uuid.Nil, true
	}
	conn, err := s.manifestPlanner().ResolveConnection(r.Context(), s.pool, ref)
	if err != nil {
		var resolveErr *accessmanifest.ResolveError
		if errors.As(err, &resolveErr) {
			respondError(w, http.StatusNotFound, resolveErr.Reason)
			return uuid.Nil, false
		}
		respondStoreError(r.Context(), w, err)
		return uuid.Nil, false
	}
	if err := s.checkConnectionScope(r.Context(), sess, conn.Environment); err != nil {
		s.respondScopeError(r.Context(), w, err)
		return uuid.Nil, false
	}
	return conn.ID, true
}

func (s *Server) planManifestForConnection(ctx context.Context, m accessmanifest.Manifest, connectionID uuid.UUID) (accessmanifest.Plan, error) {
	if connectionID == uuid.Nil {
		return s.manifestPlanner().Plan(ctx, s.pool, m)
	}
	return s.manifestPlanner().PlanForConnection(ctx, s.pool, m, connectionID)
}

func respondManifestPlanError(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, accessmanifest.ErrConnectionScopeMismatch) ||
		errors.Is(err, accessmanifest.ErrAmbiguousReplacement) {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondStoreError(ctx, w, err)
}

// planAccessManifest — POST /api/v1/access/plan (operator): dry-run diff
// манифеста (JSON или YAML — см. decodeManifestBody). Ничего не применяет;
// dangerous-действия помечены. Optional connection (UUID или display_name)
// сужает и entries, и prune до одного подключения; без него API сохраняет
// прежнюю глобальную семантику. Scope проверяется по затронутым окружениям.
func (s *Server) planAccessManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var m accessmanifest.Manifest
	if !decodeManifestBody(w, r, &m) {
		return
	}
	if err := m.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	connectionID, ok := s.resolveManifestConnectionScope(w, r, sess)
	if !ok {
		return
	}

	plan, err := s.planManifestForConnection(ctx, m, connectionID)
	if err != nil {
		respondManifestPlanError(ctx, w, err)
		return
	}
	if !s.checkManifestScope(w, r, sess, plan) {
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"plan": map[string]any{
			"actions":    plan.Actions,
			"unresolved": plan.Unresolved,
		},
		"summary": summarizePlan(plan),
	})
}

// manifestApplyChild — одно применённое действие в ответе apply.
type manifestApplyChild struct {
	Kind                     string     `json:"kind"`
	ConnectionID             uuid.UUID  `json:"connection_id"`
	AccountID                uuid.UUID  `json:"account_id"`
	AccountCreateOperationID *uuid.UUID `json:"account_create_operation_id,omitempty"`
	GrantOperationID         *uuid.UUID `json:"grant_operation_id,omitempty"`
	RevokeOperationID        *uuid.UUID `json:"revoke_operation_id,omitempty"`
	ReplaceOperationID       *uuid.UUID `json:"replace_operation_id,omitempty"`
	BindingID                *uuid.UUID `json:"binding_id,omitempty"`
	// Status — статус операции действия (grant/revoke): pending (сразу в
	// очередь) или pending_approval (ждёт явного approve: опасный грант при
	// включённом gate либо revoke массового применения, превысившего
	// GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD).
	Status operations.Status `json:"status,omitempty"`
}

// applyAccessManifest — POST /api/v1/access/apply (operator; dangerous среди
// действий требует admin и confirm=true): применяет манифест. План
// пересчитывается на сервере (клиентскому плану не доверяем). Всё выполняется
// одной транзакцией metadata database: parent-операция bulk.manifest_apply
// (сразу running) группирует дочерние account.create/access.grant/
// access.revoke, ошибка любого шага откатывает применение целиком. Optional
// connection имеет ту же safety-boundary семантику, что и у plan.
func (s *Server) applyAccessManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req manifestApplyRequest
	if !decodeManifestBody(w, r, &req) {
		return
	}
	// confirm принимается и query-параметром (?confirm=true): манифест из
	// git/export не обязан содержать транспортный флаг подтверждения, а UI
	// отправляет файл как есть, не переписывая YAML.
	if r.URL.Query().Get("confirm") == "true" {
		req.Confirm = true
	}
	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	connectionID, ok := s.resolveManifestConnectionScope(w, r, sess)
	if !ok {
		return
	}

	plan, err := s.planManifestForConnection(ctx, req.Manifest, connectionID)
	if err != nil {
		respondManifestPlanError(ctx, w, err)
		return
	}
	if !s.checkManifestScope(w, r, sess, plan) {
		return
	}
	summary := summarizePlan(plan)
	if summary.Dangerous > 0 {
		if status, msg := dangerousGrantCheck(sess.Role, req.Confirm); status != 0 {
			respondError(w, status, msg)
			return
		}
	}
	// Mass-revoke gate: если это применение отзывает больше порога bindings,
	// все его revoke-children создаются в pending_approval и не выполнятся,
	// пока admin явно не подтвердит (approve/approve-children). Порог считается
	// по пересчитанному на сервере плану и действует независимо от
	// GRANTOR_APPROVAL_REQUIRED: тот гейтит опасные привилегии, этот — масштаб
	// отзыва. Manifest apply — единственный путь, создающий несколько
	// revoke-операций одним parent (bulk-эндпоинт есть только для grants;
	// DELETE /bindings/{id} отзывает ровно один binding и под порог не
	// попадает — одиночный revoke остаётся «безопасным направлением»).
	revokesRequireApproval := approval.RequiresMassRevoke(s.massRevokeThreshold, summary.Revokes)

	s.runBulkParent(w, r, sess, bulkParent{
		kind: jobs.KindBulkManifestApply,
		payload: map[string]any{
			"actions": len(plan.Actions), "prune": req.Prune, "confirmed": req.Confirm,
		},
		payloadErrPrefix: "api: marshal manifest apply payload",
		auditAction:      auditActionManifestApplied,
		commitErrPrefix:  "api: commit manifest apply",
		extraResponse:    map[string]any{"actions_count": len(plan.Actions)},
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		connectionsToLock := make([]connections.Connection, 0, len(plan.Actions))
		for i := range plan.Actions {
			if plan.Actions[i].Kind == accessmanifest.ActionGrant && plan.Actions[i].Resolved != nil {
				connectionsToLock = append(connectionsToLock, plan.Actions[i].Resolved.Connection)
			}
		}
		if err := lockProvisioningConnections(ctx, tx, connectionsToLock); err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		// Кэши в пределах запроса: общий секрет по окружению и managed-аккаунт по
		// подключению (переиспользование как в principal-centric выдаче).
		envPaths := map[string]string{}
		accountByConn := map[uuid.UUID]inventory.Account{}
		out := make([]manifestApplyChild, 0, len(plan.Actions))
		applied := manifestSummary{}

		for i := range plan.Actions {
			act := plan.Actions[i]
			switch act.Kind {
			case accessmanifest.ActionCreateAccount:
				// Создание аккаунта выполняется в рамках парного grant через
				// ensurePrincipalAccount; отдельного шага здесь нет.
				continue
			case accessmanifest.ActionGrant:
				child, ok := s.applyManifestGrant(w, r, tx, sess, act, req.Confirm, &parentID, envPaths, accountByConn, &applied)
				if !ok {
					return nil, nil, false
				}
				out = append(out, child)
			case accessmanifest.ActionRevoke:
				child, ok := s.applyManifestRevoke(w, r, tx, sess, act, &parentID, revokesRequireApproval)
				if !ok {
					return nil, nil, false
				}
				applied.Revokes++
				out = append(out, child)
			case accessmanifest.ActionReplace:
				child, ok := s.applyManifestReplace(w, r, tx, sess, act, req.Confirm, &parentID)
				if !ok {
					return nil, nil, false
				}
				applied.Replaces++
				out = append(out, child)
			}
		}

		return out, map[string]any{
			"grants": applied.Grants, "revokes": applied.Revokes, "replaces": applied.Replaces,
			"accounts_created": applied.Creates, "prune": req.Prune,
			"revokes_pending_approval": revokesRequireApproval,
		}, true
	})
}

// applyManifestGrant применяет одно grant-действие: обеспечивает общий секрет
// принципала для окружения, находит/создаёт managed-аккаунт (с постановкой
// account.create при создании) и ставит access.grant. Пишет ответ и
// возвращает ok=false при ошибке (транзакция откатывается вызывающим).
func (s *Server) applyManifestGrant(w http.ResponseWriter, r *http.Request, tx pgx.Tx, sess auth.Session,
	act accessmanifest.Action, confirm bool, parentID *uuid.UUID,
	envPaths map[string]string, accountByConn map[uuid.UUID]inventory.Account, applied *manifestSummary) (manifestApplyChild, bool) {
	ctx := r.Context()
	ref := act.Resolved

	env := environmentOf(ref.Connection)
	identity, err := accountIdentity(ref.Connection, ref.Principal, "")
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"cannot derive account identity for connection %s: %s", ref.Connection.ID, err))
		return manifestApplyChild{}, false
	}
	if ok := s.preflightPrincipalAccountProvisioning(w, r, tx, ref.Connection, identity); !ok {
		return manifestApplyChild{}, false
	}
	sharedPath, ok := s.ensurePrincipalEnvCredential(w, r, ref.Principal.ID, env, envPaths)
	if !ok {
		return manifestApplyChild{}, false
	}
	acct, created, needsProvision, ok := s.ensurePrincipalAccount(w, r, tx, ref.Principal, ref.Connection, identity, sharedPath, accountByConn)
	if !ok {
		return manifestApplyChild{}, false
	}

	child := manifestApplyChild{Kind: accessmanifest.ActionGrant, ConnectionID: ref.Connection.ID, AccountID: acct.ID}
	if created {
		applied.Creates++
	}
	if needsProvision {
		opID, err := s.enqueueAccountProvision(r, tx, sess, acct, sharedPath, parentID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return manifestApplyChild{}, false
		}
		child.AccountCreateOperationID = &opID
	}
	grant, err := s.createGrant(r, tx, sess,
		grantTarget{account: acct, permission: ref.Permission}, nil, confirm, parentID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return manifestApplyChild{}, false
	}
	applied.Grants++
	child.GrantOperationID = &grant.OperationID
	child.BindingID = &grant.BindingID
	child.Status = grant.Status
	return child, true
}

// applyManifestReplace материализует каноническое replace-действие плана.
// Source binding остаётся одной строкой; createAccessReplacement резервирует
// смену A -> B и ставит единственного ребёнка access.replace.
func (s *Server) applyManifestReplace(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	sess auth.Session, act accessmanifest.Action, confirm bool,
	parentID *uuid.UUID) (manifestApplyChild, bool) {
	ctx := r.Context()
	ref := act.Resolved
	if ref == nil || ref.Binding == nil || ref.Account == nil {
		respondStoreError(ctx, w, errors.New("api: manifest replace action missing resolved binding or account"))
		return manifestApplyChild{}, false
	}
	fromPermission, err := s.inventory.GetPermission(ctx, tx, ref.Binding.PermissionDefinitionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return manifestApplyChild{}, false
	}
	replacement := accountRoleReplacement{
		from: accountRoleRemoval{binding: *ref.Binding, permission: fromPermission},
		to: grantTarget{
			account: *ref.Account, permission: ref.Permission,
		},
	}
	child, err := s.createAccessReplacement(r, tx, sess, replacement, confirm, parentID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return manifestApplyChild{}, false
	}
	return manifestApplyChild{
		Kind:               accessmanifest.ActionReplace,
		ConnectionID:       ref.Connection.ID,
		AccountID:          ref.Account.ID,
		ReplaceOperationID: &child.OperationID,
		BindingID:          &child.BindingID,
		Status:             child.Status,
	}, true
}

// applyManifestRevoke применяет одно revoke-действие: переводит binding в
// desired absent и ставит access.revoke дочерней parent. requiresApproval
// создаёт операцию в pending_approval (mass-revoke gate: применение отзывает
// больше GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD bindings) — job всё равно
// ставится в очередь, worker снузит его до approve, ровно как у опасных
// грантов (ADR-0010). Пишет ответ и возвращает ok=false при ошибке.
func (s *Server) applyManifestRevoke(w http.ResponseWriter, r *http.Request, tx pgx.Tx, sess auth.Session,
	act accessmanifest.Action, parentID *uuid.UUID, requiresApproval bool) (manifestApplyChild, bool) {
	ctx := r.Context()
	ref := act.Resolved
	if ref.Binding == nil || ref.Account == nil {
		respondStoreError(ctx, w, errors.New("api: manifest revoke action missing resolved binding or account"))
		return manifestApplyChild{}, false
	}
	binding := *ref.Binding
	acct := *ref.Account

	op, err := s.createRevoke(r, tx, sess, binding, acct, parentID, requiresApproval)
	if err != nil {
		respondStoreError(ctx, w, err)
		return manifestApplyChild{}, false
	}
	return manifestApplyChild{
		Kind:              accessmanifest.ActionRevoke,
		ConnectionID:      acct.ConnectionID,
		AccountID:         acct.ID,
		RevokeOperationID: &op.ID,
		BindingID:         &binding.ID,
		Status:            op.Status,
	}, true
}

// exportAccessManifest — GET /api/v1/access/export?environment=&connection=&format=&sections=
// (viewer): выгружает текущее managed-состояние доступов как манифест.
// format=json (по умолчанию) или format=yaml; YAML сериализуется из той же
// структуры Manifest (yaml-теги зеркалируют json-теги), поэтому результат
// симметричен и пригоден для повторного plan/apply в любом формате.
// connection (id или display_name) сужает выгрузку до одного подключения;
// неизвестное подключение — 404. environment, connection и format
// комбинируются.
//
// Параметр sections (managed,unmanaged,roles,accounts) расширяет export:
// без него (или при ровно managed) ответ остаётся байт-в-байт прежним
// манифестом, любая иная комбинация уходит в ветку снапшота
// (см. handlers_access_snapshot.go); неизвестное значение sections — 400.
func (s *Server) exportAccessManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !rejectUnknownQuery(w, r, "environment", "connection", "format", "sections") {
		return
	}
	format := r.URL.Query().Get("format")
	switch format {
	case "", "json", "yaml":
	default:
		respondError(w, http.StatusBadRequest, "invalid format: want json or yaml")
		return
	}
	sections, err := parseExportSections(r.URL.Query().Get("sections"))
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !manifestOnlySections(sections) {
		s.exportAccessSnapshot(w, r, format, sections)
		return
	}
	environment := r.URL.Query().Get("environment")

	// Необязательный scope по подключению: резолвится по UUID или display_name.
	// Неизвестное/неоднозначное подключение (*ResolveError) — 404 с понятным
	// текстом; прочие ошибки резолва идут общим путём.
	var connectionID uuid.UUID
	if ref := r.URL.Query().Get("connection"); ref != "" {
		conn, err := s.manifestPlanner().ResolveConnection(ctx, s.pool, ref)
		if err != nil {
			var resolveErr *accessmanifest.ResolveError
			if errors.As(err, &resolveErr) {
				respondError(w, http.StatusNotFound, resolveErr.Reason)
				return
			}
			respondStoreError(ctx, w, err)
			return
		}
		connectionID = conn.ID
	}

	manifest, err := s.manifestPlanner().Export(ctx, s.pool, environment, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if format == "yaml" {
		respondYAML(w, http.StatusOK, manifest)
		return
	}
	respondJSON(w, http.StatusOK, manifest)
}

// respondYAML пишет YAML-ответ с заданным статусом (export манифеста).
// Симметричен respondJSON: ошибка записи не возвращается — ответ уже начат.
// Отступ 2 пробела — привычный формат YAML-файлов в git.
func respondYAML(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", mediaTypeYAML)
	w.WriteHeader(status)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(body); err != nil {
		slog.Error("api: write yaml response", "error", err)
	}
	if err := enc.Close(); err != nil {
		slog.Error("api: close yaml encoder", "error", err)
	}
}
