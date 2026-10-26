package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

// resourceJSON — представление ресурса в ответах API. Дерево не
// строится: UI собирает его сам по parent_id из плоского списка.
type resourceJSON struct {
	ID            uuid.UUID       `json:"id"`
	ConnectionID  uuid.UUID       `json:"connection_id"`
	ParentID      *uuid.UUID      `json:"parent_id"`
	Kind          string          `json:"kind"`
	ExternalID    string          `json:"external_id"`
	Name          string          `json:"name"`
	CanonicalPath string          `json:"canonical_path"`
	Attributes    json.RawMessage `json:"attributes"`
	Fingerprint   string          `json:"fingerprint"`
	ObservedAt    *time.Time      `json:"observed_at"`
	Status        string          `json:"status"`
	Ownership     string          `json:"ownership"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// resourceTreeJSON — облегчённая проекция для большого дерева ресурсов.
// Attributes, fingerprint и timestamps намеренно отсутствуют: панель деталей
// читает один выбранный ресурс отдельным запросом, а дерево не переносит на
// клиент десятки тысяч тяжёлых jsonb-документов.
type resourceTreeJSON struct {
	ID           uuid.UUID  `json:"id"`
	ConnectionID uuid.UUID  `json:"connection_id"`
	ParentID     *uuid.UUID `json:"parent_id"`
	Kind         string     `json:"kind"`
	Name         string     `json:"name"`
	Status       string     `json:"status"`
	Ownership    string     `json:"ownership"`
}

// accountJSON — представление учётной записи в ответах API. vault_path —
// только путь секрета, не значение.
type accountJSON struct {
	ID                  uuid.UUID       `json:"id"`
	PrincipalID         *uuid.UUID      `json:"principal_id"`
	ConnectionID        uuid.UUID       `json:"connection_id"`
	Kind                string          `json:"kind"`
	EngineIdentity      string          `json:"engine_identity"`
	AuthenticationScope string          `json:"authentication_scope"`
	CredentialMode      *string         `json:"credential_mode"`
	VaultPath           string          `json:"vault_path"`
	Status              string          `json:"status"`
	Ownership           string          `json:"ownership"`
	Attributes          json.RawMessage `json:"attributes"`
	// DeletedAt/DeletedBy/DeleteReason — кто, когда и почему удалил
	// tombstone (status=deleted). omitempty: у живых аккаунтов и старых
	// tombstone'ов (удалены до ввода колонок) поля опускаются.
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
	DeletedBy    *string    `json:"deleted_by,omitempty"`
	DeleteReason *string    `json:"delete_reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	// Bindings — гранты аккаунта (тот же bindingJSON, что и у
	// GET /accounts/{id}/bindings). Заполняется только в списке accounts
	// connection при ?include=bindings; в остальных ответах nil и в JSON
	// опускается (список остаётся лёгким). Указатель на срез отличает
	// «не запрашивали» (nil -> поле опущено) от «запросили, но пусто»
	// (непустой указатель на []bindingJSON -> "bindings":[]).
	Bindings            *[]bindingJSON                  `json:"bindings,omitempty"`
	ProvisioningSummary *accountProvisioningSummaryJSON `json:"provisioning_summary,omitempty"`
	AccessSummary       *inventory.DirectAccessSummary  `json:"access_summary,omitempty"`
	BindingsProjection  string                          `json:"bindings_projection,omitempty"`
}

// permissionJSON — представление permission definition в ответах API.
type permissionJSON struct {
	ID              uuid.UUID       `json:"id"`
	ConnectionID    uuid.UUID       `json:"connection_id"`
	Engine          string          `json:"engine"`
	ExternalID      string          `json:"external_id"`
	Name            string          `json:"name"`
	ScopeResourceID *uuid.UUID      `json:"scope_resource_id"`
	AssignmentKey   string          `json:"assignment_key"`
	Assignable      bool            `json:"assignable"`
	Dangerous       bool            `json:"dangerous"`
	Attributes      json.RawMessage `json:"attributes"`
	// Normalized — разобранное адаптером представление права: действие,
	// ресурс, область, объяснение опасности и полное исходное выражение.
	// Разбор нотации живёт в адаптере (единственном месте, которое её знает),
	// поэтому UI ничего не парсит и одинаково показывает все движки.
	Normalized adapter.PermissionView `json:"normalized"`
	// Status — observed или missing (discovery перестал видеть право в
	// целевой системе). Отдаётся всем потребителям: вкладке «Роли» missing
	// нужен с бейджем, диалогам выдачи — для скрытия.
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// bindingJSON — представление binding в ответах API. desired_state ==
// null означает unmanaged binding (см. internal/core/inventory).
type bindingJSON struct {
	ID                             uuid.UUID       `json:"id"`
	AccountID                      uuid.UUID       `json:"account_id"`
	PermissionDefinitionID         uuid.UUID       `json:"permission_definition_id"`
	ScopeResourceID                *uuid.UUID      `json:"scope_resource_id"`
	AssignmentKey                  string          `json:"assignment_key"`
	ObservedPermissionDefinitionID *uuid.UUID      `json:"observed_permission_definition_id"`
	ObservedAttributes             json.RawMessage `json:"observed_attributes"`
	Source                         string          `json:"source"`
	DesiredState                   *string         `json:"desired_state"`
	ObservedState                  string          `json:"observed_state"`
	// ObservedEffective — наблюдаемый грант фактически действует; без него
	// UI не может зеркалить BindingNeedsRepair и отличить «выдано, но не
	// работает» от здорового права.
	ObservedEffective     bool       `json:"observed_effective"`
	Status                string     `json:"status"`
	ExpiresAt             *time.Time `json:"expires_at"`
	BindingVersion        int64      `json:"binding_version"`
	TransitionOperationID *uuid.UUID `json:"transition_operation_id"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// Обёртки списковых ответов инвентаря.
type (
	resourceListResponse struct {
		Resources []resourceJSON `json:"resources"`
	}
	resourceTreeListResponse struct {
		Resources []resourceTreeJSON `json:"resources"`
	}
	accountListResponse struct {
		Accounts []accountJSON `json:"accounts"`
	}
	permissionListResponse struct {
		Permissions []permissionJSON    `json:"permissions"`
		Inventory   *inventoryFreshness `json:"inventory,omitempty"`
	}
	bindingListResponse struct {
		Bindings []bindingJSON `json:"bindings"`
	}
)

func toResourceJSON(res inventory.Resource) resourceJSON {
	return resourceJSON{
		ID:            res.ID,
		ConnectionID:  res.ConnectionID,
		ParentID:      res.ParentID,
		Kind:          res.Kind,
		ExternalID:    res.ExternalID,
		Name:          res.Name,
		CanonicalPath: res.CanonicalPath,
		Attributes:    rawOrEmptyObject(res.Attributes),
		Fingerprint:   res.Fingerprint,
		ObservedAt:    res.ObservedAt,
		Status:        string(res.Status),
		Ownership:     string(res.Ownership),
		CreatedAt:     res.CreatedAt,
		UpdatedAt:     res.UpdatedAt,
	}
}

func toResourceTreeJSON(res inventory.ResourceTreeItem) resourceTreeJSON {
	return resourceTreeJSON{
		ID:           res.ID,
		ConnectionID: res.ConnectionID,
		ParentID:     res.ParentID,
		Kind:         res.Kind,
		Name:         res.Name,
		Status:       string(res.Status),
		Ownership:    string(res.Ownership),
	}
}

// toAccountJSON собирает accountJSON из доменной модели.
func toAccountJSON(a inventory.Account) accountJSON {
	return accountJSON{
		ID:                  a.ID,
		PrincipalID:         a.PrincipalID,
		ConnectionID:        a.ConnectionID,
		Kind:                a.Kind,
		EngineIdentity:      a.EngineIdentity,
		AuthenticationScope: a.AuthenticationScope,
		CredentialMode:      a.CredentialMode,
		VaultPath:           a.VaultPath,
		Status:              string(a.Status),
		Ownership:           string(a.Ownership),
		Attributes:          rawOrEmptyObject(a.Attributes),
		DeletedAt:           a.DeletedAt,
		DeletedBy:           a.DeletedBy,
		DeleteReason:        a.DeleteReason,
		CreatedAt:           a.CreatedAt,
		UpdatedAt:           a.UpdatedAt,
	}
}

// toBindingJSON собирает bindingJSON из доменной модели.
func toBindingJSON(b inventory.Binding) bindingJSON {
	out := bindingJSON{
		ID:                             b.ID,
		AccountID:                      b.AccountID,
		PermissionDefinitionID:         b.PermissionDefinitionID,
		ScopeResourceID:                b.ScopeResourceID,
		AssignmentKey:                  b.AssignmentKey,
		ObservedPermissionDefinitionID: b.ObservedPermissionDefinitionID,
		ObservedAttributes:             rawOrEmptyObject(b.ObservedAttributes),
		Source:                         b.Source,
		ObservedState:                  string(b.ObservedState),
		ObservedEffective:              b.ObservedEffective,
		Status:                         string(b.Status),
		ExpiresAt:                      b.ExpiresAt,
		BindingVersion:                 b.Version,
		TransitionOperationID:          b.TransitionOperationID,
		CreatedAt:                      b.CreatedAt,
		UpdatedAt:                      b.UpdatedAt,
	}
	if b.DesiredState != nil {
		desired := string(*b.DesiredState)
		out.DesiredState = &desired
	}
	return out
}

// requireConnection проверяет существование connection для вложенных
// списков инвентаря: неизвестный id — 404, пустой инвентарь существующего
// connection — 200 с пустым списком. Для operator дополнительно применяется
// scope: инвентарь connection чужого окружения — 403 (operator видит только
// свои connections, включая их ресурсы/accounts/permissions).
func (s *Server) requireConnection(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return uuid.Nil, false
	}
	environment, err := s.connections.GetEnvironment(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return uuid.Nil, false
	}
	if sess, ok := auth.FromContext(ctx); ok {
		if scopeErr := s.checkConnectionScope(ctx, sess, environment); scopeErr != nil {
			s.respondScopeError(ctx, w, scopeErr)
			return uuid.Nil, false
		}
	}
	return id, true
}

// listConnectionResources — GET /api/v1/connections/{id}/resources
// (viewer): плоский список ресурсов connection с parent_id.
func (s *Server) listConnectionResources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := s.requireConnection(w, r)
	if !ok {
		return
	}
	view := r.URL.Query().Get("view")
	if view != "" && view != "tree" {
		respondError(w, http.StatusBadRequest, "view must be empty or tree")
		return
	}
	if view == "tree" {
		items, err := s.inventory.ListResourceTree(ctx, s.pool, id)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		out := make([]resourceTreeJSON, 0, len(items))
		for i := range items {
			out = append(out, toResourceTreeJSON(items[i]))
		}
		respondJSON(w, http.StatusOK, resourceTreeListResponse{Resources: out})
		return
	}
	var resources []inventory.Resource
	var err error
	if kind := r.URL.Query().Get("kind"); kind != "" {
		resources, err = s.inventory.ListResourcesByKind(ctx, s.pool, id, kind)
	} else {
		resources, err = s.inventory.ListResources(ctx, s.pool, id)
	}
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]resourceJSON, 0, len(resources))
	for i := range resources {
		out = append(out, toResourceJSON(resources[i]))
	}
	respondJSON(w, http.StatusOK, resourceListResponse{Resources: out})
}

// getResource — GET /api/v1/resources/{id} (viewer): полная карточка одного
// ресурса для lazy detail-панели дерева.
func (s *Server) getResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	res, err := s.inventory.GetResource(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if sess, ok := auth.FromContext(ctx); ok {
		if err := s.checkConnectionScopeByID(ctx, sess, res.ConnectionID); err != nil {
			s.respondScopeError(ctx, w, err)
			return
		}
	}
	respondJSON(w, http.StatusOK, toResourceJSON(res))
}

// listConnectionAccounts — GET /api/v1/connections/{id}/accounts (viewer).
//
// По умолчанию отдаёт лёгкий список accountJSON без bindings. При
// ?include=bindings к каждому аккаунту добавляются его bindings (тот же
// bindingJSON, что и у GET /accounts/{id}/bindings), чтобы UI показал
// «уровень доступа + где» без N+1 вызовов на аккаунт (у одного connection
// их могут быть десятки). Bindings всех аккаунтов connection грузятся
// ОДНИМ запросом ListBindingsByConnection и группируются по account_id;
// порядок внутри группы совпадает с GET /accounts/{id}/bindings.
func (s *Server) listConnectionAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := s.requireConnection(w, r)
	if !ok {
		return
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	accounts, err := s.inventory.ListAccounts(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var summaries map[uuid.UUID]inventory.DirectAccessSummary
	summaryView := false
	if r.URL.Query().Get("view") == "summary" {
		conn, getErr := s.connections.Get(ctx, tx, id)
		if getErr != nil {
			respondStoreError(ctx, w, getErr)
			return
		}
		if conn.Engine == "postgres" {
			summaryView = true
			summaries, err = s.inventory.DirectAccessSummaries(ctx, tx, id)
			if err != nil {
				respondStoreError(ctx, w, err)
				return
			}
		}
	}

	var bindingsByAccount map[uuid.UUID][]bindingJSON
	if includeRequested(r, "bindings") {
		var bindings []inventory.Binding
		if summaryView {
			bindings, err = s.inventory.ListRoleBindingsByConnection(ctx, tx, id)
		} else {
			bindings, err = s.inventory.ListBindingsByConnection(ctx, tx, id)
		}
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		bindingsByAccount = make(map[uuid.UUID][]bindingJSON, len(accounts))
		for i := range bindings {
			b := bindings[i]
			bindingsByAccount[b.AccountID] = append(bindingsByAccount[b.AccountID], toBindingJSON(b))
		}
	}
	var provisioningByAccount map[uuid.UUID]accountProvisioningSummaryJSON
	if includeRequested(r, "provisioning") {
		provisioningByAccount, err = listAccountProvisioningSummaries(ctx, tx, id, accounts)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}

	out := make([]accountJSON, 0, len(accounts))
	for i := range accounts {
		aj := toAccountJSON(accounts[i])
		if summaryView {
			summary := summaries[accounts[i].ID]
			aj.AccessSummary = &summary
			aj.BindingsProjection = "roles"
		}
		if summary, ok := provisioningByAccount[accounts[i].ID]; ok {
			aj.ProvisioningSummary = &summary
		}
		if bindingsByAccount != nil {
			// Непустой указатель даже для аккаунта без bindings: поле
			// присутствует как "bindings":[], раз include=bindings запрошен.
			bs := bindingsByAccount[accounts[i].ID]
			if bs == nil {
				bs = []bindingJSON{}
			}
			aj.Bindings = &bs
		}
		out = append(out, aj)
	}
	respondJSON(w, http.StatusOK, accountListResponse{Accounts: out})
}

// includeRequested сообщает, присутствует ли want в query-параметре
// ?include (список через запятую, например ?include=bindings). Позволяет
// точечно включать «тяжёлые» части ответа, оставляя дефолт лёгким.
func includeRequested(r *http.Request, want string) bool {
	for _, part := range strings.Split(r.URL.Query().Get("include"), ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}

// listConnectionPermissions — GET /api/v1/connections/{id}/permissions
// (viewer).
func (s *Server) listConnectionPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := s.requireConnection(w, r)
	if !ok {
		return
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	conn, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var permissions []inventory.Permission
	if r.URL.Query().Get("category") == "roles" {
		permissions, err = s.inventory.ListRolePermissions(ctx, tx, id)
	} else {
		permissions, err = s.inventory.ListPermissions(ctx, tx, id)
	}
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	// Names and policy watermarks must belong to the same inventory snapshot.
	scopeNames, err := s.inventory.ResourceNamesForPermissions(ctx, tx, id, permissions)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var freshness *inventoryFreshness
	if conn.Engine == "postgres" {
		policies, err := rolepolicies.NewStore().List(ctx, tx, id)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		freshness, err = inventoryFreshnessForSnapshot(ctx, tx, conn, policies)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}

	out := make([]permissionJSON, 0, len(permissions))
	for i := range permissions {
		out = append(out, toPermissionJSON(permissions[i], scopeNames))
	}
	respondJSON(w, http.StatusOK, permissionListResponse{Permissions: out, Inventory: freshness})
}

// toPermissionJSON собирает permissionJSON и нормализованное представление.
// scopeNames — карта id ресурса в его имя в пределах подключения.
func toPermissionJSON(p inventory.Permission, scopeNames map[uuid.UUID]string) permissionJSON {
	scopeName := ""
	if p.ScopeResourceID != nil {
		scopeName = scopeNames[*p.ScopeResourceID]
	}
	return permissionJSON{
		ID:              p.ID,
		ConnectionID:    p.ConnectionID,
		Engine:          p.Engine,
		ExternalID:      p.ExternalID,
		Name:            p.Name,
		ScopeResourceID: p.ScopeResourceID,
		AssignmentKey:   p.AssignmentKey,
		Assignable:      p.Assignable,
		Dangerous:       p.Dangerous,
		Attributes:      rawOrEmptyObject(p.Attributes),
		Normalized: adapter.NormalizePermission(p.Engine, adapter.PermissionRef{
			ExternalID: p.ExternalID,
			Name:       p.Name,
			ScopeName:  scopeName,
			Assignable: p.Assignable,
			Dangerous:  p.Dangerous,
			Attributes: decodeAttributes(p.Attributes),
		}),
		Status:    string(p.Status),
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

// decodeAttributes разбирает атрибуты права из JSONB. Битые атрибуты не
// повод терять право: нормализация получит nil и деградирует до generic.
func decodeAttributes(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// listAccountBindings — GET /api/v1/accounts/{id}/bindings (viewer).
func (s *Server) listAccountBindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	account, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, account.ConnectionID)) {
		return
	}

	var bindings []inventory.Binding
	if r.URL.Query().Get("category") == "roles" {
		bindings, err = s.inventory.ListRoleBindingsByAccount(ctx, s.pool, id)
	} else {
		bindings, err = s.inventory.ListBindingsByAccount(ctx, s.pool, id)
	}
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondBindings(w, bindings)
}

// listResourceBindings — GET /api/v1/resources/{id}/bindings (viewer).
func (s *Server) listResourceBindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	resource, err := s.inventory.GetResource(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, resource.ConnectionID)) {
		return
	}

	bindings, err := s.inventory.ListBindingsByResource(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondBindings(w, bindings)
}

// respondBindings пишет список bindings в едином формате.
func respondBindings(w http.ResponseWriter, bindings []inventory.Binding) {
	out := make([]bindingJSON, 0, len(bindings))
	for i := range bindings {
		out = append(out, toBindingJSON(bindings[i]))
	}
	respondJSON(w, http.StatusOK, bindingListResponse{Bindings: out})
}
