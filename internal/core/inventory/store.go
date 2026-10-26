package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// ErrNotFound возвращается, когда запрошенная сущность инвентаря (или
// connection при сведении snapshot) не существует.
var ErrNotFound = errors.New("inventory: not found")

// Querier — минимальный контракт выполнения запросов pgx; ему
// удовлетворяют и *pgxpool.Pool, и pgx.Tx. Интерфейс объявлен локально
// (а не импортирован из core/operations), чтобы пакеты ядра не зависели
// друг от друга: структурная типизация Go делает локальные копии
// взаимозаменяемыми для вызывающего.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store — доступ к таблицам инвентаря (resources, accounts,
// permission_definitions, bindings). Не хранит соединение: Querier
// передаётся в каждый метод. Zero value полностью работоспособен.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// resourceKey идентифицирует ресурс в рамках connection так же, как
// уникальный индекс (connection_id, kind, external_id).
type resourceKey struct {
	kind       string
	externalID string
}

// UpsertSnapshot сводит discovery snapshot в metadata database
// (docs/architecture.md, раздел 9). Вызывать следует внутри транзакции,
// чтобы инвентарь не был виден наполовину сведённым.
//
// Правила:
//   - resources: fingerprint-based upsert по (connection_id, kind,
//     external_id). Изменившийся fingerprint или возврат из
//     missing/stale перезаписывают атрибуты и статус (observed) и
//     обновляют updated_at; для неизменившихся строк обновляется только
//     observed_at, updated_at сохраняется. parent_id проставляется
//     вторым проходом по ParentExternalID через map external id -> id
//     ресурсов текущего снапшота; родитель вне снапшота означает
//     корневой ресурс (parent_id = NULL);
//   - ресурсы connection, не пришедшие в снапшоте, переводятся в
//     missing, а не удаляются (удаление — retention-политика). Ресурсы
//     planned не трогаются: они существуют только как desired state и в
//     снапшоте появиться ещё не могли;
//   - accounts: upsert по (connection_id, engine_identity). Новые
//     аккаунты создаются с ownership='unmanaged' и статусом
//     active/disabled из снапшота. У существующих обновляются kind,
//     authentication_scope и attributes; status обновляется только для
//     unmanaged (у managed им управляет desired state) и для managed,
//     возвращающегося из missing, а ownership, credential_mode и
//     vault_path не перезаписываются никогда;
//   - managed-аккаунты connection, не пришедшие в снапшоте, переводятся в
//     missing (не удаляются) — но только если у connection включена
//     capability inventory.accounts, иначе пустой перечень аккаунтов
//     означает не «их нет на target», а «adapter их не собирает».
//     Аккаунты provisioning и deleted не трогаются: их статусом управляют
//     lifecycle-гварды операций;
//   - permission_definitions: upsert по (connection_id, external_id) со
//     scope_resource_id через ту же map external id -> id;
//   - bindings: наблюдаемые получают observed_state='present' (новые —
//     source='external' и desired_state NULL, у существующих source и
//     desired_state не меняются); не пришедшие в снапшоте —
//     observed_state='absent'. Status в обоих случаях вычисляется по
//     правилам ResolveBindingStatus (см. doc-комментарий пакета).
//
// Снапшот, ссылающийся на неизвестные account/permission/scope внутри
// самого себя, считается ошибкой адаптера: сведение прерывается с
// ошибкой без частичной записи (транзакция вызывающего откатится), а
// retry discovery выполнит согласованное сведение заново.
func (s *Store) UpsertSnapshot(ctx context.Context, q Querier, connectionID uuid.UUID, snap *adapter.Snapshot, observedAt time.Time) (UpsertStats, error) {
	if snap == nil {
		return UpsertStats{}, errors.New("inventory: upsert snapshot: snapshot is nil")
	}

	var engine string
	var capabilitiesJSON []byte
	err := q.QueryRow(ctx,
		`select engine, capabilities from connections where id = $1`, connectionID,
	).Scan(&engine, &capabilitiesJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UpsertStats{}, fmt.Errorf("inventory: upsert snapshot: connection %s: %w", connectionID, ErrNotFound)
		}
		return UpsertStats{}, fmt.Errorf("inventory: upsert snapshot: load connection %s: %w", connectionID, err)
	}
	var capabilities []string
	if len(capabilitiesJSON) > 0 {
		if err := json.Unmarshal(capabilitiesJSON, &capabilities); err != nil {
			return UpsertStats{}, fmt.Errorf("inventory: upsert snapshot: parse capabilities of connection %s: %w",
				connectionID, err)
		}
	}

	stats := UpsertStats{
		Resources:   len(snap.Resources),
		Accounts:    len(snap.Accounts),
		Permissions: len(snap.Permissions),
		Bindings:    len(snap.Bindings),
	}

	resourceIDs, byExternal, err := s.upsertResources(ctx, q, connectionID, snap.Resources, observedAt)
	if err != nil {
		return UpsertStats{}, err
	}
	preserved, err := preservedScopeResources(ctx, q, connectionID, snap.IncompleteScopes)
	if err != nil {
		return UpsertStats{}, err
	}
	missing, err := s.markMissingResources(ctx, q, connectionID, snap.Resources, resourceIDs, preserved)
	if err != nil {
		return UpsertStats{}, err
	}
	stats.MissingResources = missing

	accountIDs, err := s.upsertAccounts(ctx, q, connectionID, snap.Accounts)
	if err != nil {
		return UpsertStats{}, err
	}
	// Managed-аккаунт, отсутствующий в снапшоте, помечается missing — но
	// только когда снапшот действительно перечисляет учётные записи.
	// Без capability inventory.accounts пустой список означает «adapter их
	// не собирает», и пометка стёрла бы весь managed-инвентарь connection.
	if slices.Contains(capabilities, string(adapter.CapInventoryAccounts)) {
		observed := make([]string, 0, len(snap.Accounts))
		for i := range snap.Accounts {
			observed = append(observed, snap.Accounts[i].EngineIdentity)
		}
		missingAccounts, err := s.markMissingAccounts(ctx, q, connectionID, accountIDs, observed)
		if err != nil {
			return UpsertStats{}, err
		}
		stats.MissingAccounts = missingAccounts
	}
	permissionIDs, permissionAssignments, err := s.upsertPermissions(
		ctx, q, connectionID, engine, snap.Permissions, byExternal,
	)
	if err != nil {
		return UpsertStats{}, err
	}
	// Симметрия с аккаунтами: без capability inventory.permissions пустой
	// список означает «adapter права не собирает», и пометка стёрла бы
	// весь каталог прав connection.
	if slices.Contains(capabilities, string(adapter.CapInventoryPermissions)) {
		missingPermissions, err := s.markMissingPermissions(ctx, q, connectionID, permissionIDs, snap.Permissions, preserved)
		if err != nil {
			return UpsertStats{}, err
		}
		stats.MissingPermissions = missingPermissions
	}
	if err := s.syncBindingAssignmentKeys(ctx, q, connectionID); err != nil {
		return UpsertStats{}, err
	}
	if err := s.upsertBindings(ctx, q, connectionID, snap.Bindings,
		accountIDs, permissionIDs, permissionAssignments, byExternal, preserved); err != nil {
		return UpsertStats{}, err
	}
	return stats, nil
}

// upsertResources выполняет fingerprint-based upsert ресурсов и второй
// проход по parent_id. Возвращает map (kind, external_id) -> id всех
// ресурсов connection и map external_id -> id ресурсов текущего снапшота
// (для parent и scope ссылок).
func (s *Store) upsertResources(ctx context.Context, q Querier, connectionID uuid.UUID, resources []adapter.ObservedResource, observedAt time.Time) (map[resourceKey]uuid.UUID, map[string]uuid.UUID, error) {
	// «Изменился» — новый fingerprint либо возврат из missing/stale;
	// только в этом случае перезаписываются содержимое и updated_at,
	// иначе бампается лишь observed_at (см. UpsertSnapshot).
	const upsertSQL = `
		insert into resources (
			connection_id, kind, external_id, name, canonical_path,
			attributes, fingerprint, observed_at, status
		) values ($1, $2, $3, $4, $5, $6, $7, $8, 'observed')
		on conflict (connection_id, kind, external_id) do update set
			name = case when resources.fingerprint is distinct from excluded.fingerprint
					or resources.status in ('missing', 'stale', 'planned')
				then excluded.name else resources.name end,
			canonical_path = case when resources.fingerprint is distinct from excluded.fingerprint
					or resources.status in ('missing', 'stale', 'planned')
				then excluded.canonical_path else resources.canonical_path end,
			attributes = case when resources.fingerprint is distinct from excluded.fingerprint
					or resources.status in ('missing', 'stale', 'planned')
				then excluded.attributes else resources.attributes end,
			fingerprint = excluded.fingerprint,
			status = case when resources.fingerprint is distinct from excluded.fingerprint
					or resources.status in ('missing', 'stale', 'planned')
				then 'observed' else resources.status end,
			observed_at = excluded.observed_at,
			updated_at = case when resources.fingerprint is distinct from excluded.fingerprint
					or resources.status in ('missing', 'stale', 'planned')
				then now() else resources.updated_at end`

	for i := range resources {
		r := &resources[i]
		attrs, err := marshalAttributes(r.Attributes)
		if err != nil {
			return nil, nil, fmt.Errorf("inventory: upsert resource %q: marshal attributes: %w", r.ExternalID, err)
		}
		if _, err := q.Exec(ctx, upsertSQL,
			connectionID, r.Kind, r.ExternalID, r.Name, r.CanonicalPath,
			attrs, r.Fingerprint, observedAt,
		); err != nil {
			return nil, nil, fmt.Errorf("inventory: upsert resource %q: %w", r.ExternalID, err)
		}
	}

	resourceIDs, err := s.loadResourceIDs(ctx, q, connectionID)
	if err != nil {
		return nil, nil, err
	}

	// Map external_id -> id только для ресурсов текущего снапшота:
	// parent и scope ссылки адаптера задаются одним external id без
	// kind, поэтому адаптер обязан держать external id уникальным в
	// рамках connection (contract suite это проверяет).
	byExternal := make(map[string]uuid.UUID, len(resources))
	for i := range resources {
		r := &resources[i]
		id, ok := resourceIDs[resourceKey{kind: r.Kind, externalID: r.ExternalID}]
		if !ok {
			return nil, nil, fmt.Errorf("inventory: resource %q vanished during upsert", r.ExternalID)
		}
		byExternal[r.ExternalID] = id
	}

	// Второй проход: parent_id по ParentExternalID. Родитель вне
	// снапшота (или пустой) означает корневой ресурс.
	for i := range resources {
		r := &resources[i]
		var parentID *uuid.UUID
		if r.ParentExternalID != "" {
			if id, ok := byExternal[r.ParentExternalID]; ok {
				parentID = &id
			}
		}
		if _, err := q.Exec(ctx, `
			update resources set parent_id = $2, updated_at = now()
			where id = $1 and parent_id is distinct from $2`,
			byExternal[r.ExternalID], parentID,
		); err != nil {
			return nil, nil, fmt.Errorf("inventory: set parent of resource %q: %w", r.ExternalID, err)
		}
	}
	return resourceIDs, byExternal, nil
}

// loadResourceIDs строит map (kind, external_id) -> id всех ресурсов
// connection.
func (s *Store) loadResourceIDs(ctx context.Context, q Querier, connectionID uuid.UUID) (map[resourceKey]uuid.UUID, error) {
	rows, err := q.Query(ctx,
		`select id, kind, external_id from resources where connection_id = $1`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: load resource ids: %w", err)
	}
	defer rows.Close()

	ids := map[resourceKey]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var key resourceKey
		if err := rows.Scan(&id, &key.kind, &key.externalID); err != nil {
			return nil, fmt.Errorf("inventory: load resource ids: scan: %w", err)
		}
		ids[key] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: load resource ids: %w", err)
	}
	return ids, nil
}

// markMissingResources переводит в missing ресурсы connection, которые
// не пришли в снапшоте. Ресурсы planned не трогаются (см.
// UpsertSnapshot). Возвращает количество помеченных строк.
func (s *Store) markMissingResources(ctx context.Context, q Querier, connectionID uuid.UUID, resources []adapter.ObservedResource, ids map[resourceKey]uuid.UUID, preserved []uuid.UUID) (int, error) {
	present := make([]uuid.UUID, 0, len(resources))
	for i := range resources {
		r := &resources[i]
		if id, ok := ids[resourceKey{kind: r.Kind, externalID: r.ExternalID}]; ok {
			present = append(present, id)
		}
	}
	present = append(present, preserved...)
	tag, err := q.Exec(ctx, `
		update resources set status = 'missing', updated_at = now()
		where connection_id = $1
		  and status in ('observed', 'stale')
		  and not (id = any($2))`,
		connectionID, present,
	)
	if err != nil {
		return 0, fmt.Errorf("inventory: mark missing resources: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// upsertAccounts сводит наблюдаемые аккаунты и возвращает map
// engine_identity -> id всех аккаунтов connection.
func (s *Store) upsertAccounts(ctx context.Context, q Querier, connectionID uuid.UUID, accounts []adapter.ObservedAccount) (map[string]uuid.UUID, error) {
	// WHERE-guard оставляет неизменившиеся строки нетронутыми (updated_at
	// не бампается). ownership/credential_mode/vault_path отсутствуют в
	// SET сознательно; status обновляется только для unmanaged и для
	// managed-аккаунта, возвращающегося из missing (учётка снова видна на
	// target — снимаем расхождение, как это делает upsert ресурсов).
	// Managed provisioning и deleted не трогаются: их статусом управляют
	// lifecycle-гварды операций.
	const upsertSQL = `
		insert into accounts (
			connection_id, kind, engine_identity, authentication_scope,
			status, ownership, attributes
		) values ($1, $2, $3, $4, $5, 'unmanaged', $6)
		on conflict (connection_id, engine_identity) do update set
			-- kind управляемой учётки сохраняется. В PostgreSQL disable
			-- ставит NOLOGIN, и следующий discovery видит роль без логина,
			-- то есть group: учётка «замуровывалась» — enable/rotate/share
			-- начинали отвечать 409 «это роль», а вернуть её можно было
			-- только руками в СУБД. Управляемая учётка остаётся учётной
			-- записью независимо от того, как выглядит в движке.
			kind = case when accounts.ownership = 'managed'
				then accounts.kind else excluded.kind end,
			authentication_scope = excluded.authentication_scope,
			attributes = excluded.attributes,
			status = case when accounts.ownership = 'unmanaged' or accounts.status = 'missing'
				then excluded.status else accounts.status end,
			updated_at = now()
		where (accounts.ownership <> 'managed' and accounts.kind is distinct from excluded.kind)
		   or accounts.authentication_scope is distinct from excluded.authentication_scope
		   or accounts.attributes is distinct from excluded.attributes
		   or ((accounts.ownership = 'unmanaged' or accounts.status = 'missing')
		       and accounts.status is distinct from excluded.status)`

	for i := range accounts {
		a := &accounts[i]
		attrs, err := marshalAttributes(a.Attributes)
		if err != nil {
			return nil, fmt.Errorf("inventory: upsert account %q: marshal attributes: %w", a.EngineIdentity, err)
		}
		status := AccountActive
		if a.Disabled {
			status = AccountDisabled
		}
		if _, err := q.Exec(ctx, upsertSQL,
			connectionID, a.Kind, a.EngineIdentity, a.AuthenticationScope, status, attrs,
		); err != nil {
			return nil, fmt.Errorf("inventory: upsert account %q: %w", a.EngineIdentity, err)
		}
	}

	rows, err := q.Query(ctx,
		`select id, engine_identity from accounts where connection_id = $1`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: load account ids: %w", err)
	}
	defer rows.Close()

	ids := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var identity string
		if err := rows.Scan(&id, &identity); err != nil {
			return nil, fmt.Errorf("inventory: load account ids: scan: %w", err)
		}
		ids[identity] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: load account ids: %w", err)
	}
	return ids, nil
}

// managedAccountIdentities возвращает engine identity управляемых живых
// УЧЁТНЫХ ЗАПИСЕЙ подключения. Используется, чтобы не публиковать
// собственную учётку как назначаемое право (см. upsertPermissions).
//
// Роли-контейнеры (kind='group') исключены сознательно: управляемая роль без
// логина — это ровно то, что grantor завёл, чтобы выдавать её людям
// (role.create, ADR-0020). Правило защищает от выдачи чужих привилегий вместе
// с учёткой, а у роли своих привилегий владельца нет — она сама и есть право.
func (s *Store) managedAccountIdentities(ctx context.Context, q Querier, connectionID uuid.UUID) (map[string]bool, error) {
	rows, err := q.Query(ctx, `
		select engine_identity from accounts
		where connection_id = $1 and ownership = 'managed'
		  and status <> 'deleted' and kind <> 'group'`,
		connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: load managed account identities: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return nil, fmt.Errorf("inventory: scan managed account identity: %w", err)
		}
		out[identity] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: load managed account identities: %w", err)
	}
	return out, nil
}

// upsertPermissions сводит наблюдаемые permissions и возвращает map
// external_id -> id всех permissions connection.
func (s *Store) upsertPermissions(ctx context.Context, q Querier, connectionID uuid.UUID, engine string,
	permissions []adapter.ObservedPermission, resourceByExternal map[string]uuid.UUID,
) (map[string]uuid.UUID, map[string]string, error) {
	// Возврат права из missing — тоже изменение: наблюдаемое в снапшоте
	// право всегда становится observed, updated_at при этом бампается.
	const upsertSQL = `
			insert into permission_definitions (
				connection_id, engine, external_id, name,
				scope_resource_id, assignment_key, assignable, dangerous, attributes, status
			) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'observed')
			on conflict (connection_id, external_id) do update set
				name = excluded.name,
				scope_resource_id = excluded.scope_resource_id,
				assignment_key = case
					when permission_definitions.assignment_key = '' then excluded.assignment_key
					else permission_definitions.assignment_key
				end,
				assignable = excluded.assignable,
			dangerous = excluded.dangerous,
			attributes = excluded.attributes,
			status = 'observed',
			updated_at = now()
			where permission_definitions.name is distinct from excluded.name
			   or permission_definitions.scope_resource_id is distinct from excluded.scope_resource_id
			   or (permission_definitions.assignment_key = '' and excluded.assignment_key <> '')
		   or permission_definitions.assignable is distinct from excluded.assignable
		   or permission_definitions.dangerous is distinct from excluded.dangerous
		   or permission_definitions.attributes is distinct from excluded.attributes
		   or permission_definitions.status = 'missing'`

	// Учётные записи синхронизируются раньше прав, поэтому managed-состояние
	// уже известно. Право, которое в движке является той же сущностью, что и
	// управляемая учётка (PostgreSQL: выключенная учётка становится NOLOGIN
	// и внешне неотличима от роли), назначаемым не публикуется: выдача
	// такого «права» другому принципалу передала бы ему все привилегии
	// владельца учётки.
	managedIdentities, err := s.managedAccountIdentities(ctx, q, connectionID)
	if err != nil {
		return nil, nil, err
	}

	for i := range permissions {
		p := &permissions[i]
		if p.AccountEngineIdentity != "" && managedIdentities[p.AccountEngineIdentity] {
			p.Assignable = false
		}
		attrs, err := marshalAttributes(p.Attributes)
		if err != nil {
			return nil, nil, fmt.Errorf("inventory: upsert permission %q: marshal attributes: %w", p.ExternalID, err)
		}
		var scopeID *uuid.UUID
		if p.ScopeExternalID != "" {
			id, ok := resourceByExternal[p.ScopeExternalID]
			if !ok {
				return nil, nil, fmt.Errorf("inventory: permission %q references unknown scope resource %q",
					p.ExternalID, p.ScopeExternalID)
			}
			scopeID = &id
		}
		if _, err := q.Exec(ctx, upsertSQL,
			connectionID, engine, p.ExternalID, p.Name,
			scopeID, p.AssignmentKey, p.Assignable, p.Dangerous, attrs,
		); err != nil {
			return nil, nil, fmt.Errorf("inventory: upsert permission %q: %w", p.ExternalID, err)
		}
	}

	rows, err := q.Query(ctx,
		`select id, external_id, assignment_key
		 from permission_definitions where connection_id = $1`, connectionID)
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: load permission ids: %w", err)
	}
	defer rows.Close()

	ids := map[string]uuid.UUID{}
	assignments := map[string]string{}
	for rows.Next() {
		var id uuid.UUID
		var externalID, assignmentKey string
		if err := rows.Scan(&id, &externalID, &assignmentKey); err != nil {
			return nil, nil, fmt.Errorf("inventory: load permission ids: scan: %w", err)
		}
		ids[externalID] = id
		assignments[externalID] = assignmentKey
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("inventory: load permission ids: %w", err)
	}
	for i := range permissions {
		observed := permissions[i]
		if observed.AssignmentKey != "" && assignments[observed.ExternalID] != observed.AssignmentKey {
			return nil, nil, fmt.Errorf(
				"inventory: permission %q assignment key changed from %q to %q",
				observed.ExternalID, assignments[observed.ExternalID], observed.AssignmentKey,
			)
		}
	}
	return ids, assignments, nil
}

// markMissingPermissions помечает missing права connection, не пришедшие в
// снапшоте. Строки не удаляются: на них ссылаются bindings, в том числе
// managed с desired=present — такое расхождение оператор обязан видеть.
// Идемпотентно: уже missing строка повторно не обновляется.
func (s *Store) markMissingPermissions(ctx context.Context, q Querier, connectionID uuid.UUID, ids map[string]uuid.UUID, observed []adapter.ObservedPermission, preserved []uuid.UUID) (int, error) {
	present := make([]uuid.UUID, 0, len(observed))
	for i := range observed {
		if id, ok := ids[observed[i].ExternalID]; ok {
			present = append(present, id)
		}
	}
	tag, err := q.Exec(ctx, `
		update permission_definitions set status = 'missing', updated_at = now()
		where connection_id = $1
		  and status = 'observed'
		  and not (id = any($2))
		  and not coalesce(scope_resource_id = any($3::uuid[]),false)`,
		connectionID, present, preserved,
	)
	if err != nil {
		return 0, fmt.Errorf("inventory: mark missing permissions: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// syncBindingAssignmentKeys переносит assignment_key permission definition на
// существующий binding. Это нужно при первом discovery после включения
// templates: managed binding уже существует, а slot должен занять именно он,
// чтобы observed template обновил ту же строку, а не создал phantom twin.
func (s *Store) syncBindingAssignmentKeys(ctx context.Context, q Querier, connectionID uuid.UUID) error {
	_, err := q.Exec(ctx, `
		update bindings b set assignment_key = p.assignment_key, updated_at = now()
		from permission_definitions p, accounts a
		where p.id = b.permission_definition_id
		  and a.id = b.account_id
		  and a.connection_id = $1
		  and b.assignment_key = ''
		  and p.assignment_key <> ''`, connectionID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("inventory: sync binding assignment keys: duplicate exclusive assignment slot: %w", err)
		}
		return fmt.Errorf("inventory: sync binding assignment keys: %w", err)
	}
	return nil
}

// upsertBindings сводит наблюдаемые bindings и помечает absent те
// bindings connection, что не пришли в снапшоте. Non-exclusive bindings
// продолжают конфликтовать по exact permission/scope. Exclusive bindings
// конфликтуют по (account, assignment_key): managed строка сохраняет desired
// permission, unmanaged — переезжает на exact observed permission.
func (s *Store) upsertBindings(ctx context.Context, q Querier, connectionID uuid.UUID,
	bindings []adapter.ObservedBinding, accountIDs, permissionIDs map[string]uuid.UUID,
	permissionAssignments map[string]string, resourceByExternal map[string]uuid.UUID,
	preserved []uuid.UUID,
) error {
	// ResolveBindingStatus для observed='present': desired NULL — status
	// прежний, desired='present' — synced, desired='absent' — drift.
	// updated_at бампается только при видимом изменении, чтобы повторное
	// сведение того же снапшота было идемпотентным.
	// $4 — признак унаследованного binding: право получено не напрямую, а
	// через роль или группу (adapter.ObservedBinding.Inherited).
	//
	// source='service' при конфликте сохраняется: binding, который выдал
	// grantor, остаётся управляемым, даже если та же связь ещё и
	// наследуется. Потерять managed-признак значило бы потерять кнопку
	// отзыва и вывести право из-под управления.
	const nonExclusiveUpsertSQL = `
			insert into bindings (
				account_id, permission_definition_id, scope_resource_id,
				source, desired_state, observed_state, status, observed_effective,
				observed_permission_definition_id, observed_attributes
			) values ($1, $2, $3,
				case when $4::bool then 'inherited' else 'external' end,
				null, 'present', 'observed', $5::bool, $2, $6::jsonb)
			on conflict (account_id, permission_definition_id, scope_resource_id) do update set
				observed_state = 'present',
				observed_effective = $5::bool,
				observed_permission_definition_id = $2,
				observed_attributes = $6::jsonb,
				source = case
				when bindings.source = 'service' then bindings.source
				when $4::bool then 'inherited'
				else 'external'
			end,
			status = case
				-- Право существует, но не действует: обещанного доступа нет,
				-- значит это дрифт, а не synced (см. ResolveBindingStatus).
				when bindings.desired_state = 'present' and not $5::bool then 'drift'
				when bindings.desired_state = 'present' then 'synced'
				when bindings.desired_state = 'absent' then 'drift'
				-- Непринятое право (desired_state IS NULL) остаётся
				-- наблюдаемым, а не «ожидающим применения».
				when bindings.desired_state is null then 'observed'
				else bindings.status
			end,
				updated_at = case
					when bindings.observed_state is distinct from 'present'
					  or bindings.observed_effective is distinct from $5::bool
					  or bindings.observed_permission_definition_id is distinct from $2
					  or bindings.observed_attributes is distinct from $6::jsonb
				  or (bindings.desired_state = 'present' and $5::bool and bindings.status <> 'synced')
				  or (bindings.desired_state = 'present' and not $5::bool and bindings.status <> 'drift')
				  or (bindings.desired_state = 'absent' and bindings.status <> 'drift')
				  or (bindings.source <> 'service'
				      and bindings.source is distinct from
				          case when $4::bool then 'inherited' else 'external' end)
				then now() else bindings.updated_at
			end
			returning id`

	const exclusiveUpsertSQL = `
		insert into bindings (
			account_id, permission_definition_id, scope_resource_id, assignment_key,
			source, desired_state, observed_state, status, observed_effective,
			observed_permission_definition_id, observed_attributes
		) values ($1, $2, $3, $6,
			case when $4::bool then 'inherited' else 'external' end,
			null, 'present', 'observed', $5::bool, $2, $7::jsonb)
		on conflict (account_id, assignment_key) where assignment_key <> '' do update set
			permission_definition_id = case
				when bindings.desired_state is null then excluded.permission_definition_id
				else bindings.permission_definition_id
			end,
			scope_resource_id = case
				when bindings.desired_state is null then excluded.scope_resource_id
				else bindings.scope_resource_id
			end,
			observed_state = 'present',
			observed_permission_definition_id = excluded.observed_permission_definition_id,
			observed_attributes = excluded.observed_attributes,
			observed_effective = excluded.observed_effective,
			source = case
				when bindings.source = 'service' then bindings.source
				when $4::bool then 'inherited'
				else 'external'
			end,
			status = case
				when bindings.transition_operation_id is not null then bindings.status
				when bindings.desired_state = 'present'
				 and (bindings.permission_definition_id is distinct from excluded.observed_permission_definition_id
				      or not excluded.observed_effective) then 'drift'
				when bindings.desired_state = 'present' then 'synced'
				when bindings.desired_state = 'absent' then 'drift'
				else 'observed'
			end,
			updated_at = case
				when bindings.observed_state is distinct from 'present'
				  or bindings.observed_permission_definition_id is distinct from excluded.observed_permission_definition_id
				  or bindings.observed_attributes is distinct from excluded.observed_attributes
				  or bindings.observed_effective is distinct from excluded.observed_effective
				  or (bindings.desired_state is null
				      and bindings.permission_definition_id is distinct from excluded.permission_definition_id)
				  or (bindings.desired_state is null
				      and bindings.scope_resource_id is distinct from excluded.scope_resource_id)
				  or bindings.status is distinct from case
					when bindings.transition_operation_id is not null then bindings.status
					when bindings.desired_state = 'present'
					 and (bindings.permission_definition_id is distinct from excluded.observed_permission_definition_id
					      or not excluded.observed_effective) then 'drift'
					when bindings.desired_state = 'present' then 'synced'
					when bindings.desired_state = 'absent' then 'drift'
					else 'observed' end
				  or (bindings.source <> 'service'
				      and bindings.source is distinct from
				          case when $4::bool then 'inherited' else 'external' end)
				then now() else bindings.updated_at
			end
		returning id`

	present := make([]uuid.UUID, 0, len(bindings))
	seenAssignmentSlots := make(map[string]string)
	for i := range bindings {
		b := &bindings[i]
		accountID, ok := accountIDs[b.AccountEngineIdentity]
		if !ok {
			return fmt.Errorf("inventory: binding references unknown account %q", b.AccountEngineIdentity)
		}
		permissionID, ok := permissionIDs[b.PermissionExternalID]
		if !ok {
			return fmt.Errorf("inventory: binding references unknown permission %q", b.PermissionExternalID)
		}
		var scopeID *uuid.UUID
		if b.ScopeExternalID != "" {
			id, ok := resourceByExternal[b.ScopeExternalID]
			if !ok {
				return fmt.Errorf("inventory: binding references unknown scope resource %q", b.ScopeExternalID)
			}
			scopeID = &id
		}
		var id uuid.UUID
		effective := adapter.BindingEffective(b.Attributes)
		observedAttributes, err := marshalAttributes(b.Attributes)
		if err != nil {
			return fmt.Errorf("inventory: upsert binding %q -> %q: marshal observed attributes: %w",
				b.AccountEngineIdentity, b.PermissionExternalID, err)
		}
		assignmentKey := permissionAssignments[b.PermissionExternalID]
		if b.AssignmentKey != "" {
			if assignmentKey == "" {
				return fmt.Errorf("inventory: binding %q -> %q declares assignment key %q but permission has none",
					b.AccountEngineIdentity, b.PermissionExternalID, b.AssignmentKey)
			}
			if assignmentKey != b.AssignmentKey {
				return fmt.Errorf("inventory: binding %q -> %q assignment key %q does not match permission key %q",
					b.AccountEngineIdentity, b.PermissionExternalID, b.AssignmentKey, assignmentKey)
			}
		}
		if assignmentKey != "" {
			slot := b.AccountEngineIdentity + "\x00" + assignmentKey
			if previous, duplicate := seenAssignmentSlots[slot]; duplicate {
				return fmt.Errorf(
					"inventory: snapshot contains multiple permissions %q and %q in assignment slot %q for account %q",
					previous, b.PermissionExternalID, assignmentKey, b.AccountEngineIdentity,
				)
			}
			seenAssignmentSlots[slot] = b.PermissionExternalID
		}
		query := nonExclusiveUpsertSQL
		args := []any{accountID, permissionID, scopeID, b.Inherited, effective, observedAttributes}
		if assignmentKey != "" {
			query = exclusiveUpsertSQL
			args = []any{accountID, permissionID, scopeID, b.Inherited, effective, assignmentKey, observedAttributes}
		}
		if err := q.QueryRow(ctx, query, args...).Scan(&id); err != nil {
			return fmt.Errorf("inventory: upsert binding %q -> %q: %w",
				b.AccountEngineIdentity, b.PermissionExternalID, err)
		}
		present = append(present, id)
	}

	// ResolveBindingStatus для observed='absent': desired NULL — status
	// прежний (unmanaged доступ пропал сам, drift не ставим),
	// desired='present' — drift, desired='absent' — synced.
	if _, err := q.Exec(ctx, `
			update bindings b set
				observed_state = 'absent',
				observed_permission_definition_id = null,
				observed_attributes = '{}'::jsonb,
				status = case
					when b.transition_operation_id is not null then b.status
					when b.desired_state = 'present' then 'drift'
					when b.desired_state = 'absent' then 'synced'
					else b.status
				end,
			updated_at = now()
		from accounts a
		where a.id = b.account_id
		  and a.connection_id = $1
		  and not (b.id = any($2))
		  and not coalesce(b.scope_resource_id = any($3::uuid[]),false)
			  and (b.observed_state is distinct from 'absent'
			       or b.observed_permission_definition_id is not null
			       or b.observed_attributes is distinct from '{}'::jsonb
			       or (b.transition_operation_id is null and b.desired_state = 'present' and b.status <> 'drift')
			       or (b.transition_operation_id is null and b.desired_state = 'absent' and b.status <> 'synced'))`,
		connectionID, present, preserved,
	); err != nil {
		return fmt.Errorf("inventory: mark absent bindings: %w", err)
	}
	return nil
}

func preservedScopeResources(ctx context.Context, q Querier, connectionID uuid.UUID, scopes []string) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0)
	if len(scopes) == 0 {
		return ids, nil
	}
	rows, err := q.Query(ctx, `with recursive unavailable as (
	 select id from resources where connection_id=$1 and external_id=any($2::text[])
	 union select r.id from resources r join unavailable u on r.parent_id=u.id where r.connection_id=$1
	) select id from unavailable`, connectionID, scopes)
	if err != nil {
		return nil, fmt.Errorf("inventory: preserve unavailable scopes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// marshalAttributes кодирует атрибуты в jsonb; nil map становится пустым
// объектом. json.Marshal сортирует ключи map, поэтому одинаковое
// содержимое всегда даёт одинаковые байты — это важно для
// change-детекции в upsert.
func marshalAttributes(attrs map[string]any) ([]byte, error) {
	if attrs == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// resourceColumns — список колонок resources, согласованный со
// scanResource.
const resourceColumns = `id, connection_id, parent_id, kind, external_id, name,
	canonical_path, attributes, fingerprint, observed_at, status, ownership,
	created_at, updated_at`

// ListResources возвращает ресурсы connection в детерминированном
// порядке (kind, external_id).
func (s *Store) ListResources(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Resource, error) {
	rows, err := q.Query(ctx,
		`select `+resourceColumns+` from resources
		 where connection_id = $1 order by kind, external_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list resources: %w", err)
	}
	defer rows.Close()

	var out []Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: list resources: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list resources: %w", err)
	}
	return out, nil
}

// ListResourceTree возвращает только поля, необходимые для дерева. В отличие
// от ListResources запрос не читает тяжёлые jsonb attributes и fingerprint у
// каждого объекта большого PostgreSQL-кластера.
func (s *Store) ListResourceTree(ctx context.Context, q Querier, connectionID uuid.UUID) ([]ResourceTreeItem, error) {
	rows, err := q.Query(ctx, `
		select id, connection_id, parent_id, kind, name, status, ownership
		from resources where connection_id = $1 order by kind, external_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list resource tree: %w", err)
	}
	defer rows.Close()

	var out []ResourceTreeItem
	for rows.Next() {
		var item ResourceTreeItem
		if err := rows.Scan(
			&item.ID, &item.ConnectionID, &item.ParentID, &item.Kind,
			&item.Name, &item.Status, &item.Ownership,
		); err != nil {
			return nil, fmt.Errorf("inventory: list resource tree: scan: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list resource tree: %w", err)
	}
	return out, nil
}

// GetResource возвращает ресурс по id. Если его нет — ErrNotFound.
func (s *Store) GetResource(ctx context.Context, q Querier, id uuid.UUID) (Resource, error) {
	r, err := scanResource(q.QueryRow(ctx,
		`select `+resourceColumns+` from resources where id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Resource{}, fmt.Errorf("inventory: get resource %s: %w", id, ErrNotFound)
		}
		return Resource{}, fmt.Errorf("inventory: get resource %s: %w", id, err)
	}
	return r, nil
}

// scanResource читает одну строку resources; порядок полей обязан
// совпадать с resourceColumns.
func scanResource(row pgx.Row) (Resource, error) {
	var r Resource
	var attrs []byte
	err := row.Scan(
		&r.ID, &r.ConnectionID, &r.ParentID, &r.Kind, &r.ExternalID, &r.Name,
		&r.CanonicalPath, &attrs, &r.Fingerprint, &r.ObservedAt, &r.Status,
		&r.Ownership, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return Resource{}, err
	}
	r.Attributes = attrs
	return r, nil
}

// ListAccounts возвращает аккаунты connection в порядке engine_identity.
func (s *Store) ListAccounts(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Account, error) {
	rows, err := q.Query(ctx, `
		select id, principal_id, connection_id, kind, engine_identity,
		       authentication_scope, credential_mode, vault_path, status,
		       ownership, attributes, deleted_at, deleted_by, delete_reason,
		       lifecycle_version, created_at, updated_at
		from accounts where connection_id = $1 order by engine_identity`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list accounts: %w", err)
	}
	defer rows.Close()

	var out []Account
	for rows.Next() {
		var a Account
		var attrs []byte
		if err := rows.Scan(
			&a.ID, &a.PrincipalID, &a.ConnectionID, &a.Kind, &a.EngineIdentity,
			&a.AuthenticationScope, &a.CredentialMode, &a.VaultPath, &a.Status,
			&a.Ownership, &attrs, &a.DeletedAt, &a.DeletedBy, &a.DeleteReason,
			&a.LifecycleVersion, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("inventory: list accounts: scan: %w", err)
		}
		a.Attributes = attrs
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list accounts: %w", err)
	}
	return out, nil
}

// permissionColumns — список колонок permission_definitions,
// согласованный со scanPermission.
const permissionColumns = `id, connection_id, engine, external_id, name,
	scope_resource_id, assignment_key, assignable, dangerous, attributes, status,
	created_at, updated_at`

// scanPermission читает одну строку permission_definitions; порядок полей
// обязан совпадать с permissionColumns.
func scanPermission(row pgx.Row) (Permission, error) {
	var p Permission
	var attrs []byte
	err := row.Scan(
		&p.ID, &p.ConnectionID, &p.Engine, &p.ExternalID, &p.Name,
		&p.ScopeResourceID, &p.AssignmentKey, &p.Assignable, &p.Dangerous, &attrs, &p.Status,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return Permission{}, err
	}
	p.Attributes = attrs
	return p, nil
}

// ListPermissions возвращает permissions connection в порядке
// external_id.
func (s *Store) ListPermissions(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Permission, error) {
	rows, err := q.Query(ctx,
		`select `+permissionColumns+` from permission_definitions
		 where connection_id = $1 order by external_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list permissions: %w", err)
	}
	defer rows.Close()

	var out []Permission
	for rows.Next() {
		p, err := scanPermission(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: list permissions: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list permissions: %w", err)
	}
	return out, nil
}

// bindingColumns — список колонок bindings, согласованный со
// scanBinding.
const bindingColumns = `id, account_id, permission_definition_id, scope_resource_id,
	assignment_key, observed_permission_definition_id, observed_attributes,
	source, desired_state, observed_state, observed_effective, status, expires_at,
	binding_version, transition_operation_id, created_at, updated_at`

// ListBindingsByAccount возвращает bindings аккаунта в порядке создания.
func (s *Store) ListBindingsByAccount(ctx context.Context, q Querier, accountID uuid.UUID) ([]Binding, error) {
	return s.listBindings(ctx, q, `account_id = $1`, accountID)
}

// ListBindingsByResource возвращает bindings со scope на указанный
// ресурс в порядке создания.
func (s *Store) ListBindingsByResource(ctx context.Context, q Querier, resourceID uuid.UUID) ([]Binding, error) {
	return s.listBindings(ctx, q, `scope_resource_id = $1`, resourceID)
}

// bindingColumnsB — те же колонки bindings, что и bindingColumns, но с
// префиксом алиаса b для запросов с join на accounts (иначе id/status/
// created_at/updated_at неоднозначны — они есть и в accounts).
const bindingColumnsB = `b.id, b.account_id, b.permission_definition_id, b.scope_resource_id,
	b.assignment_key, b.observed_permission_definition_id, b.observed_attributes,
	b.source, b.desired_state, b.observed_state, b.observed_effective, b.status,
	b.expires_at, b.binding_version, b.transition_operation_id, b.created_at, b.updated_at`

// ListBindingsByConnection возвращает bindings всех аккаунтов connection
// одним запросом (join bindings -> accounts по connection_id). Порядок —
// account_id, затем created_at, id: это позволяет вызывающему сгруппировать
// результат по account_id, а внутри каждой группы порядок совпадает с
// ListBindingsByAccount (created_at, id). Метод существует, чтобы список
// accounts connection обогащался их bindings одним запросом вместо N+1
// вызовов ListBindingsByAccount (см. listConnectionAccounts в internal/api).
func (s *Store) ListBindingsByConnection(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Binding, error) {
	rows, err := q.Query(ctx,
		`select `+bindingColumnsB+` from bindings b
		 join accounts a on a.id = b.account_id
		 where a.connection_id = $1
		 order by b.account_id, b.created_at, b.id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list bindings by connection: %w", err)
	}
	defer rows.Close()

	var out []Binding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: list bindings by connection: scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list bindings by connection: %w", err)
	}
	return out, nil
}

// listBindings выполняет выборку bindings по условию с одним аргументом.
// Условие — константа вызывающего метода, не внешний ввод.
func (s *Store) listBindings(ctx context.Context, q Querier, where string, arg any) ([]Binding, error) {
	rows, err := q.Query(ctx,
		`select `+bindingColumns+` from bindings where `+where+` order by created_at, id`, arg)
	if err != nil {
		return nil, fmt.Errorf("inventory: list bindings: %w", err)
	}
	defer rows.Close()

	var out []Binding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: list bindings: scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list bindings: %w", err)
	}
	return out, nil
}

// scanBinding читает одну строку bindings; порядок полей обязан
// совпадать с bindingColumns.
func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	var desired *string
	var observedAttributes []byte
	err := row.Scan(
		&b.ID, &b.AccountID, &b.PermissionDefinitionID, &b.ScopeResourceID,
		&b.AssignmentKey, &b.ObservedPermissionDefinitionID, &observedAttributes,
		&b.Source, &desired, &b.ObservedState, &b.ObservedEffective, &b.Status,
		&b.ExpiresAt, &b.Version, &b.TransitionOperationID, &b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		return Binding{}, err
	}
	if desired != nil {
		state := BindingState(*desired)
		b.DesiredState = &state
	}
	b.ObservedAttributes = observedAttributes
	return b, nil
}

// DriftSummary возвращает сводку расхождений по connection: unmanaged
// bindings (source='external', desired_state IS NULL), bindings в drift,
// managed-ресурсы в missing и managed-аккаунты, которых нет в целевой
// системе (missing после discovery либо неподтверждённый provisioning).
// Условия обязаны совпадать с выборками DriftFindings.
func (s *Store) DriftSummary(ctx context.Context, q Querier, connectionID uuid.UUID) (DriftCounters, error) {
	summaries, err := s.DriftSummaries(ctx, q, []uuid.UUID{connectionID})
	if err != nil {
		return DriftCounters{}, fmt.Errorf("inventory: drift summary: %w", err)
	}
	return summaries[connectionID], nil
}
