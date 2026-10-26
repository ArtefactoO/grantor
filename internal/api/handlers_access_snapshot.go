package api

// Снапшот доступов подключения — расширение GET /api/v1/access/export
// query-параметром sections (managed,unmanaged,roles,accounts). Без sections
// (или ровно managed) export остаётся байт-в-байт прежним манифестом; любая
// другая комбинация отдаёт документ kind=access_snapshot — фактический
// аудит-снимок одного подключения, который НЕ является манифестом и не
// пригоден для POST /api/v1/access/apply (apply отвергает его валидацией:
// у снапшота нет version/entries).
//
// Секретов снапшот не несёт: только имена и идентификаторы (engine identity,
// имена ролей/ресурсов, external id принципалов). Vault paths аккаунтов
// намеренно опущены целиком.

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/accessmanifest"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// accessSnapshotKind — значение поля kind документа снапшота: явный маркер,
// отличающий его от манифеста (у которого поле version).
const accessSnapshotKind = "access_snapshot"

// Допустимые значения query-параметра sections экспорта доступов.
const (
	sectionManaged   = "managed"
	sectionUnmanaged = "unmanaged"
	sectionRoles     = "roles"
	sectionAccounts  = "accounts"
)

// parseExportSections разбирает query-параметр sections: значения
// managed/unmanaged/roles/accounts через запятую, дубликаты схлопываются.
// Пустой параметр — nil (export остаётся чистым манифестом). Неизвестное
// или пустое значение в списке — ошибка (400 у вызывающего).
func parseExportSections(raw string) (map[string]bool, error) {
	if raw == "" {
		return nil, nil
	}
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		section := strings.TrimSpace(part)
		switch section {
		case sectionManaged, sectionUnmanaged, sectionRoles, sectionAccounts:
			out[section] = true
		default:
			return nil, fmt.Errorf("invalid sections value %q: want %s, %s, %s or %s",
				section, sectionManaged, sectionUnmanaged, sectionRoles, sectionAccounts)
		}
	}
	return out, nil
}

// manifestOnlySections сообщает, что запрошен чистый managed-манифест:
// sections отсутствует или равен ровно managed. Этот путь обязан оставаться
// байт-в-байт совместимым с прежним export (результат пригоден для apply).
func manifestOnlySections(sections map[string]bool) bool {
	return len(sections) == 0 || (len(sections) == 1 && sections[sectionManaged])
}

// snapshotConnection — блок connection снапшота: идентификация подключения
// без каких-либо реквизитов доступа.
type snapshotConnection struct {
	ID          uuid.UUID `json:"id" yaml:"id"`
	DisplayName string    `json:"display_name" yaml:"display_name"`
	Engine      string    `json:"engine" yaml:"engine"`
	Environment string    `json:"environment" yaml:"environment"`
}

// snapshotManagedEntry — запись секции managed. В отличие от манифеста
// (строго principal → role, переприменяемый), снапшот показывает ВСЁ, чем
// управляет grantor в подключении: и права аккаунтов без привязанного
// принципала (principal пуст), и scoped-гранты (scope) — их манифест
// пропускает. Account заполнен всегда (engine identity аккаунта).
type snapshotManagedEntry struct {
	Principal string `json:"principal,omitempty" yaml:"principal,omitempty"`
	Account   string `json:"account" yaml:"account"`
	Role      string `json:"role" yaml:"role"`
	Scope     string `json:"scope,omitempty" yaml:"scope,omitempty"`
	State     string `json:"state" yaml:"state"`
}

// snapshotUnmanagedBinding — запись секции unmanaged: обнаруженный discovery
// binding без принятого решения (desired_state IS NULL). Role — имя
// permission definition; Scope — имя ресурса, если binding не
// connection-wide.
type snapshotUnmanagedBinding struct {
	Account       string `json:"account" yaml:"account"`
	Role          string `json:"role" yaml:"role"`
	Scope         string `json:"scope,omitempty" yaml:"scope,omitempty"`
	ObservedState string `json:"observed_state" yaml:"observed_state"`
}

// snapshotRole — запись секции roles: permission definition подключения.
type snapshotRole struct {
	Name       string `json:"name" yaml:"name"`
	ExternalID string `json:"external_id" yaml:"external_id"`
	Assignable bool   `json:"assignable" yaml:"assignable"`
	Dangerous  bool   `json:"dangerous" yaml:"dangerous"`
	Scope      string `json:"scope,omitempty" yaml:"scope,omitempty"`
}

// snapshotAccount — запись секции accounts: инвентарь учётных записей.
// Principal — внешняя ссылка привязанного принципала (external_subject,
// при его отсутствии display_name); vault path намеренно не выгружается.
type snapshotAccount struct {
	EngineIdentity string `json:"engine_identity" yaml:"engine_identity"`
	Kind           string `json:"kind" yaml:"kind"`
	Ownership      string `json:"ownership" yaml:"ownership"`
	Status         string `json:"status" yaml:"status"`
	Principal      string `json:"principal,omitempty" yaml:"principal,omitempty"`
}

// accessSnapshot — документ снапшота доступов одного подключения.
// Присутствуют ТОЛЬКО запрошенные секции (указатели на срезы: запрошенная
// пустая секция сериализуется как [], незапрошенная опускается). Снапшот —
// фактический аудит-снимок, НЕ манифест: повторно применить его через
// POST /api/v1/access/apply нельзя (валидация apply отвергает документ без
// version/entries). yaml-теги зеркалируют json-теги (см. Entry в
// core/accessmanifest).
type accessSnapshot struct {
	Kind        string                      `json:"kind" yaml:"kind"`
	Connection  snapshotConnection          `json:"connection" yaml:"connection"`
	GeneratedAt time.Time                   `json:"generated_at" yaml:"generated_at"`
	Managed     *[]snapshotManagedEntry     `json:"managed,omitempty" yaml:"managed,omitempty"`
	Unmanaged   *[]snapshotUnmanagedBinding `json:"unmanaged,omitempty" yaml:"unmanaged,omitempty"`
	Roles       *[]snapshotRole             `json:"roles,omitempty" yaml:"roles,omitempty"`
	Accounts    *[]snapshotAccount          `json:"accounts,omitempty" yaml:"accounts,omitempty"`
}

// snapshotSourceData — заранее загруженные данные для сборки снапшота.
// Каждый срез загружается одним store-запросом и только когда нужен
// запрошенным секциям (см. exportAccessSnapshot).
type snapshotSourceData struct {
	accounts    []inventory.Account
	permissions []inventory.Permission
	resources   []inventory.Resource
	bindings    []inventory.Binding
	principals  map[uuid.UUID]principals.Principal
}

// snapshotPrincipalRef — читаемая ссылка на принципала в снапшоте:
// external_subject, при его отсутствии display_name (та же семантика, что
// у principalRef в core/accessmanifest).
func snapshotPrincipalRef(p principals.Principal) string {
	if p.ExternalSubject != "" {
		return p.ExternalSubject
	}
	return p.DisplayName
}

// buildAccessSnapshot — чистая сборка документа снапшота из загруженных
// данных: заполняет только запрошенные секции, разрешает ссылки
// binding -> account/permission/resource по переданным срезам и держит
// порядок детерминированным (managed — как в export манифеста; unmanaged —
// account/role/scope; roles и accounts — порядок store-запросов:
// external_id и engine_identity соответственно).
func buildAccessSnapshot(conn connections.Connection, generatedAt time.Time,
	sections map[string]bool, data snapshotSourceData) accessSnapshot {
	snap := accessSnapshot{
		Kind: accessSnapshotKind,
		Connection: snapshotConnection{
			ID:          conn.ID,
			DisplayName: conn.DisplayName,
			Engine:      conn.Engine,
			Environment: conn.Environment,
		},
		GeneratedAt: generatedAt,
	}

	resourceName := func(id *uuid.UUID) string {
		if id == nil {
			return ""
		}
		for i := range data.resources {
			if data.resources[i].ID == *id {
				return data.resources[i].Name
			}
		}
		return id.String()
	}

	// В managed-секцию снапшота, в отличие от манифеста, входит ВСЁ
	// управляемое: права аккаунтов без привязанного принципала и
	// scoped-гранты. Строится из инвентаря (managed-аккаунты × managed
	// bindings), принципал резолвится когда привязан.
	if sections[sectionManaged] {
		accountByID := make(map[uuid.UUID]inventory.Account, len(data.accounts))
		for i := range data.accounts {
			accountByID[data.accounts[i].ID] = data.accounts[i]
		}
		externalByPermission := make(map[uuid.UUID]string, len(data.permissions))
		for i := range data.permissions {
			externalByPermission[data.permissions[i].ID] = data.permissions[i].ExternalID
		}
		managed := make([]snapshotManagedEntry, 0)
		for i := range data.bindings {
			b := data.bindings[i]
			if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
				continue
			}
			acct, ok := accountByID[b.AccountID]
			if !ok || acct.Ownership != inventory.OwnershipManaged || acct.Status == inventory.AccountDeleted {
				continue
			}
			principal := ""
			if acct.PrincipalID != nil {
				if p, ok := data.principals[*acct.PrincipalID]; ok {
					principal = snapshotPrincipalRef(p)
				}
			}
			role, ok := externalByPermission[b.PermissionDefinitionID]
			if !ok {
				role = b.PermissionDefinitionID.String()
			}
			managed = append(managed, snapshotManagedEntry{
				Principal: principal,
				Account:   acct.EngineIdentity,
				Role:      role,
				Scope:     resourceName(b.ScopeResourceID),
				State:     string(accessmanifest.StatePresent),
			})
		}
		slices.SortFunc(managed, func(a, b snapshotManagedEntry) int {
			if c := strings.Compare(a.Account, b.Account); c != 0 {
				return c
			}
			if c := strings.Compare(a.Role, b.Role); c != 0 {
				return c
			}
			return strings.Compare(a.Scope, b.Scope)
		})
		snap.Managed = &managed
	}

	if sections[sectionUnmanaged] {
		identityByAccount := make(map[uuid.UUID]string, len(data.accounts))
		for i := range data.accounts {
			identityByAccount[data.accounts[i].ID] = data.accounts[i].EngineIdentity
		}
		nameByPermission := make(map[uuid.UUID]string, len(data.permissions))
		for i := range data.permissions {
			nameByPermission[data.permissions[i].ID] = data.permissions[i].Name
		}
		unmanaged := make([]snapshotUnmanagedBinding, 0)
		for i := range data.bindings {
			b := data.bindings[i]
			if b.DesiredState != nil {
				continue
			}
			account, ok := identityByAccount[b.AccountID]
			if !ok {
				account = b.AccountID.String()
			}
			role, ok := nameByPermission[b.PermissionDefinitionID]
			if !ok {
				role = b.PermissionDefinitionID.String()
			}
			unmanaged = append(unmanaged, snapshotUnmanagedBinding{
				Account:       account,
				Role:          role,
				Scope:         resourceName(b.ScopeResourceID),
				ObservedState: string(b.ObservedState),
			})
		}
		slices.SortFunc(unmanaged, func(a, b snapshotUnmanagedBinding) int {
			if c := strings.Compare(a.Account, b.Account); c != 0 {
				return c
			}
			if c := strings.Compare(a.Role, b.Role); c != 0 {
				return c
			}
			return strings.Compare(a.Scope, b.Scope)
		})
		snap.Unmanaged = &unmanaged
	}

	if sections[sectionRoles] {
		roles := make([]snapshotRole, 0, len(data.permissions))
		for i := range data.permissions {
			p := data.permissions[i]
			roles = append(roles, snapshotRole{
				Name:       p.Name,
				ExternalID: p.ExternalID,
				Assignable: p.Assignable,
				Dangerous:  p.Dangerous,
				Scope:      resourceName(p.ScopeResourceID),
			})
		}
		snap.Roles = &roles
	}

	if sections[sectionAccounts] {
		accounts := make([]snapshotAccount, 0, len(data.accounts))
		for i := range data.accounts {
			a := data.accounts[i]
			item := snapshotAccount{
				EngineIdentity: a.EngineIdentity,
				Kind:           a.Kind,
				Ownership:      string(a.Ownership),
				Status:         string(a.Status),
			}
			if a.PrincipalID != nil {
				if p, ok := data.principals[*a.PrincipalID]; ok {
					item.Principal = snapshotPrincipalRef(p)
				}
			}
			accounts = append(accounts, item)
		}
		snap.Accounts = &accounts
	}

	return snap
}

// exportAccessSnapshot — ветка снапшота GET /api/v1/access/export (viewer):
// sections содержит что-то кроме ровно managed. Требует параметр connection
// (снапшот всегда одного подключения; environment здесь не применяется).
// Данные каждой секции читаются одним store-запросом; принципалы для секции
// accounts — одним ListByIDs по уникальным principal_id. Формат ответа —
// общий с манифестом (format=json|yaml, тот же YAML-энкодер respondYAML).
func (s *Server) exportAccessSnapshot(w http.ResponseWriter, r *http.Request, format string, sections map[string]bool) {
	ctx := r.Context()
	ref := r.URL.Query().Get("connection")
	if ref == "" {
		respondError(w, http.StatusBadRequest,
			"sections other than managed require the connection parameter")
		return
	}
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

	var data snapshotSourceData
	if sections[sectionManaged] || sections[sectionUnmanaged] || sections[sectionAccounts] {
		if data.accounts, err = s.inventory.ListAccounts(ctx, s.pool, conn.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if sections[sectionManaged] || sections[sectionUnmanaged] || sections[sectionRoles] {
		if data.permissions, err = s.inventory.ListPermissions(ctx, s.pool, conn.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if data.resources, err = s.inventory.ListResources(ctx, s.pool, conn.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if sections[sectionManaged] || sections[sectionUnmanaged] {
		if data.bindings, err = s.inventory.ListBindingsByConnection(ctx, s.pool, conn.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if sections[sectionManaged] || sections[sectionAccounts] {
		ids := make([]uuid.UUID, 0)
		seen := map[uuid.UUID]bool{}
		for i := range data.accounts {
			pid := data.accounts[i].PrincipalID
			if pid == nil || seen[*pid] {
				continue
			}
			seen[*pid] = true
			ids = append(ids, *pid)
		}
		list, err := s.principals.ListByIDs(ctx, s.pool, ids)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		data.principals = make(map[uuid.UUID]principals.Principal, len(list))
		for i := range list {
			data.principals[list[i].ID] = list[i]
		}
	}

	snap := buildAccessSnapshot(conn, time.Now().UTC(), sections, data)
	if format == "yaml" {
		respondYAML(w, http.StatusOK, snap)
		return
	}
	respondJSON(w, http.StatusOK, snap)
}
