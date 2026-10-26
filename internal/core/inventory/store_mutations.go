package inventory

// Точечные read/write-методы инвентаря для operation engine и мутирующих
// API endpoints (этап 1b). Discovery-сведение живёт в store.go и правил
// этого файла не касается: здесь desired state задаётся явно сервисом,
// ownership managed-аккаунтов принадлежит grantor.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// ErrAlreadyExists возвращается при попытке создать сущность, которая
// уже существует (конфликт уникального ключа).
var (
	ErrAlreadyExists = errors.New("inventory: already exists")
	// ErrBindingAlreadyPresent означает, что точное назначение permission +
	// scope уже находится в desired_state=present. Повторный grant не должен
	// создавать вторую операцию поверх того же desired state.
	ErrBindingAlreadyPresent = errors.New("inventory: binding is already present")
	// ErrAssignmentOccupied означает, что exclusive permission slot аккаунта
	// уже занят другой desired permission. Замена должна переиспользовать эту
	// строку атомарным A→B transition, а не создавать второй binding.
	ErrAssignmentOccupied = errors.New("inventory: binding assignment slot is occupied")
	// ErrAccountStatusConflict означает, что account не находится в
	// ожидаемом состоянии для запрошенной мутации.
	ErrAccountStatusConflict = errors.New("inventory: account status conflict")
	// ErrAccountLifecycleConflict означает, что job относится к прежнему
	// поколению account lifecycle и не вправе трогать Vault/target.
	ErrAccountLifecycleConflict = errors.New("inventory: account lifecycle conflict")
	// ErrAccountLifecycleBusy означает, что у account уже есть незавершённая
	// lifecycle-операция; параллельное резервирование версии запрещено.
	ErrAccountLifecycleBusy = errors.New("inventory: account lifecycle operation is already pending")
)

// pgUniqueViolation и pgForeignKeyViolation — SQLSTATE-коды PostgreSQL,
// которые методы записи переводят в доменные ошибки.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

// accountColumns — список колонок accounts, согласованный со scanAccount.
// Дублирует перечень в ListAccounts сознательно: store.go принадлежит
// discovery-сведению и здесь не переписывается.
const accountColumns = `id, principal_id, connection_id, kind, engine_identity,
	authentication_scope, credential_mode, vault_path, status, ownership,
	attributes, deleted_at, deleted_by, delete_reason, lifecycle_version,
	created_at, updated_at`

// scanAccount читает одну строку accounts; порядок полей обязан совпадать
// с accountColumns.
func scanAccount(row pgx.Row) (Account, error) {
	var a Account
	var attrs []byte
	err := row.Scan(
		&a.ID, &a.PrincipalID, &a.ConnectionID, &a.Kind, &a.EngineIdentity,
		&a.AuthenticationScope, &a.CredentialMode, &a.VaultPath, &a.Status,
		&a.Ownership, &attrs, &a.DeletedAt, &a.DeletedBy, &a.DeleteReason,
		&a.LifecycleVersion, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return Account{}, err
	}
	a.Attributes = attrs
	return a, nil
}

// GetAccount возвращает учётную запись по id. Если её нет — ErrNotFound.
func (s *Store) GetAccount(ctx context.Context, q Querier, id uuid.UUID) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx,
		`select `+accountColumns+` from accounts where id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, fmt.Errorf("inventory: get account %s: %w", id, ErrNotFound)
		}
		return Account{}, fmt.Errorf("inventory: get account %s: %w", id, err)
	}
	return a, nil
}

// PreparePurgeDeletedAccount блокирует tombstone до завершения purge и
// проверяет, что параллельная lifecycle-операция не сможет восстановить или
// изменить account между зачисткой Vault и удалением metadata.
func (s *Store) PreparePurgeDeletedAccount(ctx context.Context, q Querier, id uuid.UUID) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx,
		`select `+accountColumns+` from accounts where id = $1 for update`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, fmt.Errorf("inventory: prepare purge account %s: %w", id, ErrNotFound)
		}
		return Account{}, fmt.Errorf("inventory: prepare purge account %s: %w", id, err)
	}
	if a.Status != AccountDeleted {
		return Account{}, fmt.Errorf("inventory: prepare purge account %s: expected deleted, got %s: %w",
			id, a.Status, ErrAccountStatusConflict)
	}
	var busy bool
	if err := q.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1
			  and status in ('pending_approval', 'pending', 'running')
		)`, id).Scan(&busy); err != nil {
		return Account{}, fmt.Errorf("inventory: prepare purge account %s: inspect lifecycle operations: %w", id, err)
	}
	if busy {
		return Account{}, fmt.Errorf("inventory: prepare purge account %s: unfinished operation exists: %w",
			id, ErrAccountLifecycleBusy)
	}
	return a, nil
}

// PurgeDeletedAccount безвозвратно удаляет metadata tombstone аккаунта.
// Исторические operations переживают удаление благодаря ON DELETE SET NULL,
// bindings удаляются FK-каскадом. Незавершённая операция блокирует purge:
// иначе queued restore мог бы применить identity в target уже после очистки
// metadata.
func (s *Store) PurgeDeletedAccount(ctx context.Context, q Querier, id uuid.UUID) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx, `
		delete from accounts a
		where a.id = $1
		  and a.status = 'deleted'
		  and not exists (
			select 1 from operations o
			where o.account_id = a.id
			  and o.status in ('pending_approval', 'pending', 'running')
		  )
		returning `+accountColumns, id))
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Account{}, fmt.Errorf("inventory: purge account %s: %w", id, err)
	}
	current, getErr := s.GetAccount(ctx, q, id)
	if getErr != nil {
		return Account{}, fmt.Errorf("inventory: purge account %s: %w", id, getErr)
	}
	if current.Status != AccountDeleted {
		return Account{}, fmt.Errorf("inventory: purge account %s: expected deleted, got %s: %w",
			id, current.Status, ErrAccountStatusConflict)
	}
	return Account{}, fmt.Errorf("inventory: purge account %s: unfinished operation exists: %w",
		id, ErrAccountLifecycleBusy)
}

// FindAccountByIdentity возвращает учётную запись по естественному
// уникальному ключу (connection_id, engine_identity). Если её нет —
// ErrNotFound. Используется principal-centric flow для проверки, не занята
// ли identity перед созданием managed-аккаунта.
func (s *Store) FindAccountByIdentity(ctx context.Context, q Querier, connectionID uuid.UUID, engineIdentity string) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx,
		`select `+accountColumns+` from accounts where connection_id = $1 and engine_identity = $2`,
		connectionID, engineIdentity))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, fmt.Errorf(
				"inventory: find account %q in connection %s: %w", engineIdentity, connectionID, ErrNotFound)
		}
		return Account{}, fmt.Errorf(
			"inventory: find account %q in connection %s: %w", engineIdentity, connectionID, err)
	}
	return a, nil
}

// GetBinding возвращает binding по id. Если его нет — ErrNotFound.
func (s *Store) GetBinding(ctx context.Context, q Querier, id uuid.UUID) (Binding, error) {
	b, err := scanBinding(q.QueryRow(ctx,
		`select `+bindingColumns+` from bindings where id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, fmt.Errorf("inventory: get binding %s: %w", id, ErrNotFound)
		}
		return Binding{}, fmt.Errorf("inventory: get binding %s: %w", id, err)
	}
	return b, nil
}

// GetPermission возвращает permission definition по id. Если его нет —
// ErrNotFound.
func (s *Store) GetPermission(ctx context.Context, q Querier, id uuid.UUID) (Permission, error) {
	p, err := scanPermission(q.QueryRow(ctx,
		`select `+permissionColumns+` from permission_definitions where id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Permission{}, fmt.Errorf("inventory: get permission %s: %w", id, ErrNotFound)
		}
		return Permission{}, fmt.Errorf("inventory: get permission %s: %w", id, err)
	}
	return p, nil
}

// ConnectionInventoryCounts — счётчики инвентаря connection для guard и
// audit удаления подключения (см. deleteConnection в internal/api).
// Resources и Accounts — сколько строк удалит FK-каскад при удалении
// connection; ManagedAccounts — сколько среди аккаунтов реально созданных
// grantor пользователей (ownership='managed'), которые останутся
// осиротевшими в целевой системе (grantor их метаданные забудет, но на
// целевом кластере не тронет).
type ConnectionInventoryCounts struct {
	Resources       int
	Accounts        int
	ManagedAccounts int
}

// CountConnectionInventory считает инвентарь connection одним запросом:
// все ресурсы, все аккаунты и managed-аккаунты (ownership='managed',
// status<>'deleted'). Managed-счётчик исключает soft-deleted аккаунты:
// их реальный пользователь в целевой системе уже удалён отдельной
// операцией, осиротить нечего — они не должны блокировать удаление
// connection. Deleted-строки при этом всё равно попадают в общий Accounts
// (FK-каскад удалит и их).
func (s *Store) CountConnectionInventory(ctx context.Context, q Querier, connectionID uuid.UUID) (ConnectionInventoryCounts, error) {
	var c ConnectionInventoryCounts
	err := q.QueryRow(ctx, `
		select
			(select count(*) from resources where connection_id = $1),
			(select count(*) from accounts where connection_id = $1),
			(select count(*) from accounts
			  where connection_id = $1 and ownership = 'managed' and status <> 'deleted')`,
		connectionID,
	).Scan(&c.Resources, &c.Accounts, &c.ManagedAccounts)
	if err != nil {
		return ConnectionInventoryCounts{}, fmt.Errorf("inventory: count connection inventory: %w", err)
	}
	return c, nil
}

// CreateManagedAccountParams — параметры создания managed-аккаунта.
// CredentialMode и VaultPath могут быть пустыми: пустой mode пишется как
// NULL, путь дозаполняется SetAccountVaultPath после записи в Vault.
type CreateManagedAccountParams struct {
	ConnectionID   uuid.UUID
	EngineIdentity string
	PrincipalID    *uuid.UUID
	CredentialMode string
	VaultPath      string
	// Kind — вид учётной записи; пусто = login. 'group' заводит
	// роль-контейнер без логина (role.create): она не аутентифицируется и
	// существует, чтобы выдаваться другим учётным записям как право.
	Kind string
}

// CreateManagedAccount создаёт managed login-аккаунт в статусе active.
// Конфликт по (connection_id, engine_identity) — ErrAlreadyExists (в том
// числе когда identity уже занята unmanaged-аккаунтом из discovery);
// несуществующий connection или principal — ErrNotFound.
func (s *Store) CreateManagedAccount(ctx context.Context, q Querier, params CreateManagedAccountParams) (Account, error) {
	if params.EngineIdentity == "" {
		return Account{}, errors.New("inventory: create managed account: engine identity is empty")
	}
	a, err := scanAccount(q.QueryRow(ctx, `
		insert into accounts (
			principal_id, connection_id, kind, engine_identity,
			credential_mode, vault_path, status, ownership
		) values ($1, $2, coalesce(nullif($6, ''), 'login'), $3, nullif($4, ''), $5, 'active', 'managed')
		returning `+accountColumns,
		params.PrincipalID, params.ConnectionID, params.EngineIdentity,
		params.CredentialMode, params.VaultPath, params.Kind,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				return Account{}, fmt.Errorf(
					"inventory: create managed account: identity %q is already taken in connection %s: %w",
					params.EngineIdentity, params.ConnectionID, ErrAlreadyExists)
			case pgForeignKeyViolation:
				return Account{}, fmt.Errorf(
					"inventory: create managed account: referenced connection or principal: %w", ErrNotFound)
			}
		}
		return Account{}, fmt.Errorf("inventory: create managed account %q: %w", params.EngineIdentity, err)
	}
	return a, nil
}

// SetAccountStatus обновляет статус учётной записи (active|disabled|
// deleted — CHECK схемы). Несуществующий id — ErrNotFound.
func (s *Store) SetAccountStatus(ctx context.Context, q Querier, id uuid.UUID, status AccountStatus) error {
	tag, err := q.Exec(ctx,
		`update accounts set status = $2, updated_at = now() where id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("inventory: set account %s status %q: %w", id, status, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("inventory: set account %s status: %w", id, ErrNotFound)
	}
	return nil
}

// ReserveAccountLifecycle атомарно резервирует следующее поколение account
// для новой lifecycle-операции. Guard проверяет ожидаемый status и отсутствие
// другой незавершенной account.* или credential операции. Метод должен
// вызываться в той же транзакции, что и создание operations/job.
//
// Возвращённые status/version записываются в payload операции. Сама операция
// вставляется ПОСЛЕ этого UPDATE: конкурентный запрос ждёт row lock, затем
// видит уже закоммиченную активную операцию и не инвалидирует первый job.
func (s *Store) ReserveAccountLifecycle(ctx context.Context, q Querier, id uuid.UUID, expected AccountStatus) (Account, error) {
	// Явный row lock важен: два UPDATE с NOT EXISTS в одном statement могли
	// бы оба использовать snapshot, созданный до ожидания concurrent commit.
	// Следующий statement после FOR UPDATE получает свежий READ COMMITTED
	// snapshot и видит operation, вставленную владельцем предыдущего lock.
	current, err := scanAccount(q.QueryRow(ctx,
		`select `+accountColumns+` from accounts where id = $1 for update`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, fmt.Errorf("inventory: reserve account %s lifecycle: %w", id, ErrNotFound)
		}
		return Account{}, fmt.Errorf("inventory: reserve account %s lifecycle: lock: %w", id, err)
	}
	if current.Status != expected {
		return Account{}, fmt.Errorf(
			"inventory: reserve account %s lifecycle: status %q, expected %q: %w",
			id, current.Status, expected, ErrAccountStatusConflict)
	}
	var busy bool
	if err := q.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1
			  and status in ('pending_approval', 'pending', 'running')
			  and (kind like 'account.%' or kind like 'postgres.account.%' or
                   kind like 'postgres.role.create.%' or kind in ('role.create', 'credential.rotate', 'credential.verify'))
        ) or exists (
            select 1 from river_job j join operations o on
                j.args->>'operation_id'=o.id::text or (j.args->'next_operation_ids') ? o.id::text
            where o.account_id=$1 and o.status not in ('success','cancelled') and
                j.state not in ('completed','cancelled','discarded')
              and (o.kind like 'postgres.account.provision.%' or
                   o.kind like 'postgres.account.verify_creation.%' or o.kind='credential.verify')
        ) or exists (
            select 1 from bindings
            where account_id = $1 and transition_operation_id is not null
        )`, id).Scan(&busy); err != nil {
		return Account{}, fmt.Errorf("inventory: reserve account %s lifecycle: inspect active operation: %w", id, err)
	}
	if busy {
		return Account{}, fmt.Errorf("inventory: reserve account %s lifecycle: %w", id, ErrAccountLifecycleBusy)
	}
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts set lifecycle_version = lifecycle_version + 1, updated_at = now()
		where id = $1 and status = $2 and lifecycle_version = $3
		returning `+accountColumns, id, expected, current.LifecycleVersion))
	if err != nil {
		return Account{}, fmt.Errorf("inventory: reserve account %s lifecycle: update: %w", id, err)
	}
	return a, nil
}

// EnsureNoActiveAccessOperations is the extra gate for account.enable.
// Desired permissions are restored by enable, therefore a grant that still
// waits for approval/pending execution must be resolved first; otherwise
// enable could apply its desired state without the original approval path.
func (s *Store) EnsureNoActiveAccessOperations(ctx context.Context, q Querier, accountID uuid.UUID) error {
	var busy bool
	if err := q.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1 and kind like 'access.%'
			  and status in ('pending_approval', 'pending', 'running')
		)`, accountID).Scan(&busy); err != nil {
		return fmt.Errorf("inventory: inspect active access operations of account %s: %w", accountID, err)
	}
	if busy {
		return fmt.Errorf("inventory: account %s has an unfinished access operation: %w",
			accountID, ErrAccountLifecycleBusy)
	}
	return nil
}

// CheckAccountLifecycle проверяет status и зарезервированную версию перед
// любым внешним side effect. Нулевая версия payload допустима только для
// legacy job на account поколения 0; после первого reserve такой job
// становится stale и отклоняется.
func CheckAccountLifecycle(a Account, expectedStatus AccountStatus, expectedVersion int64) error {
	if a.LifecycleVersion != expectedVersion {
		return fmt.Errorf("account %s lifecycle version %d, expected %d: %w",
			a.ID, a.LifecycleVersion, expectedVersion, ErrAccountLifecycleConflict)
	}
	if expectedStatus != "" && a.Status != expectedStatus {
		return fmt.Errorf("account %s status %q, expected %q: %w",
			a.ID, a.Status, expectedStatus, ErrAccountStatusConflict)
	}
	return nil
}

// SetAccountStatusGuarded завершает enable/disable только если account всё
// ещё относится к тому же lifecycle-поколению и исходному status.
func (s *Store) SetAccountStatusGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedStatus, status AccountStatus, expectedVersion int64) error {
	tag, err := q.Exec(ctx, `
		update accounts set status = $3, updated_at = now()
		where id = $1 and status = $2 and lifecycle_version = $4`,
		id, expectedStatus, status, expectedVersion)
	if err != nil {
		return fmt.Errorf("inventory: set account %s status %q: %w", id, status, err)
	}
	if tag.RowsAffected() == 0 {
		current, getErr := s.GetAccount(ctx, q, id)
		if getErr != nil {
			return getErr
		}
		return CheckAccountLifecycle(current, expectedStatus, expectedVersion)
	}
	return nil
}

// SetAccountVaultPath обновляет vault path учётной записи. Несуществующий
// id — ErrNotFound.
func (s *Store) SetAccountVaultPath(ctx context.Context, q Querier, id uuid.UUID, path string) error {
	tag, err := q.Exec(ctx,
		`update accounts set vault_path = $2, updated_at = now() where id = $1`, id, path)
	if err != nil {
		return fmt.Errorf("inventory: set account %s vault path: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("inventory: set account %s vault path: %w", id, ErrNotFound)
	}
	return nil
}

// SetAccountManaged переводит учётную запись под управление grantor
// (ownership='managed') и фиксирует применённый credential: непустой
// vaultPath перезаписывает vault_path, непустой credentialMode — режим
// credential; пустые значения оставляют колонки прежними. Используется
// adopt-flow (metadata-режим — только ownership) и success-хвостом
// credential.rotate (путь секрета + режим при первом появлении
// credential). Метод идемпотентен: повтор на уже managed-аккаунте
// безвреден. Несуществующий id — ErrNotFound.
func (s *Store) SetAccountManaged(ctx context.Context, q Querier, id uuid.UUID, vaultPath, credentialMode string) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts set
			ownership = 'managed',
			vault_path = case when $2 = '' then vault_path else $2 end,
			credential_mode = coalesce(nullif($3, ''), credential_mode),
			updated_at = now()
		where id = $1
		returning `+accountColumns, id, vaultPath, credentialMode))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, fmt.Errorf("inventory: set account %s managed: %w", id, ErrNotFound)
		}
		return Account{}, fmt.Errorf("inventory: set account %s managed: %w", id, err)
	}
	return a, nil
}

// SetAccountManagedGuarded — lifecycle-guarded вариант SetAccountManaged для
// credential.rotate/adopt. Он не позволяет старому job записать Vault path
// или ownership после перехода account в новое поколение.
func (s *Store) SetAccountManagedGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedStatus AccountStatus, expectedVersion int64, vaultPath, credentialMode string) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts set
			ownership = 'managed',
			vault_path = case when $4 = '' then vault_path else $4 end,
			credential_mode = coalesce(nullif($5, ''), credential_mode),
			updated_at = now()
		where id = $1 and status = $2 and lifecycle_version = $3
		returning `+accountColumns, id, expectedStatus, expectedVersion, vaultPath, credentialMode))
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Account{}, fmt.Errorf("inventory: set account %s managed guarded: %w", id, err)
	}
	current, getErr := s.GetAccount(ctx, q, id)
	if getErr != nil {
		return Account{}, getErr
	}
	return Account{}, CheckAccountLifecycle(current, expectedStatus, expectedVersion)
}

// SetAccountManagedLinkedGuarded атомарно завершает link-and-manage:
// ownership, shared Vault ref, credential mode и principal link появляются
// только после успешных rotate + proof в worker.
func (s *Store) SetAccountManagedLinkedGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedStatus AccountStatus, expectedVersion int64, principalID uuid.UUID, vaultPath string) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts set
			ownership = 'managed', principal_id = $4,
			vault_path = $5, credential_mode = 'existing_vault_ref',
			updated_at = now()
		where id = $1 and status = $2 and lifecycle_version = $3
		returning `+accountColumns, id, expectedStatus, expectedVersion, principalID, vaultPath))
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Account{}, fmt.Errorf("inventory: set account %s managed linked guarded: %w", id, err)
	}
	current, getErr := s.GetAccount(ctx, q, id)
	if getErr != nil {
		return Account{}, getErr
	}
	return Account{}, CheckAccountLifecycle(current, expectedStatus, expectedVersion)
}

// MarkAccountDeleted помечает учётную запись удалённой (status='deleted')
// и удаляет её bindings. Строка account сознательно НЕ удаляется:
//
//  1. история операций сохраняет ссылку на аккаунт;
//  2. физический DELETE через FK `operations.account_id ON DELETE SET NULL`
//     обновил бы строку ТЕКУЩЕЙ операции, которую держит внешняя
//     транзакция worker — executor во второй транзакции ждал бы её
//     коммита до JobTimeout (self-deadlock, невидимый для PostgreSQL).
//
// Удаление bindings безопасно: мутации и discovery по connection
// сериализуются advisory lock, а завершённые операции не держат блокировок.
//
// deletedBy — актор операции account.delete, reason — необязательная
// причина удаления (пустые значения пишутся как NULL). Повтор идемпотентной
// операции перезаписывает deleted_at/deleted_by/delete_reason теми же
// значениями — это безвредно.
func (s *Store) MarkAccountDeleted(ctx context.Context, q Querier, id uuid.UUID, deletedBy, reason string) error {
	if _, err := q.Exec(ctx, `delete from bindings where account_id = $1`, id); err != nil {
		return fmt.Errorf("inventory: delete bindings of account %s: %w", id, err)
	}
	tag, err := q.Exec(ctx, `
		update accounts set
			status = 'deleted',
			deleted_at = now(),
			deleted_by = nullif($2, ''),
			delete_reason = nullif($3, ''),
			updated_at = now()
		where id = $1`, id, deletedBy, reason)
	if err != nil {
		return fmt.Errorf("inventory: mark account %s deleted: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("inventory: mark account %s deleted: %w", id, ErrNotFound)
	}
	return nil
}

// MarkAccountDeletedGuarded фиксирует tombstone только для зарезервированного
// поколения и допустимого исходного active/disabled status. Bindings удаляются
// после row guard, в той же транзакции.
func (s *Store) MarkAccountDeletedGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedStatus AccountStatus, expectedVersion int64, deletedBy, reason string) error {
	// Сериализуем status guard с EnsureBinding: иначе grant мог проверить
	// active, вставить binding между DELETE bindings и status=deleted и
	// оставить binding на tombstone.
	current, err := scanAccount(q.QueryRow(ctx,
		`select `+accountColumns+` from accounts where id = $1 for update`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("inventory: mark account %s deleted: %w", id, ErrNotFound)
		}
		return fmt.Errorf("inventory: mark account %s deleted: lock: %w", id, err)
	}
	if err := CheckAccountLifecycle(current, expectedStatus, expectedVersion); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `delete from bindings where account_id = $1`, id); err != nil {
		return fmt.Errorf("inventory: delete bindings of account %s: %w", id, err)
	}
	tag, err := q.Exec(ctx, `
		update accounts set
			status = 'deleted', deleted_at = now(),
			deleted_by = nullif($4, ''), delete_reason = nullif($5, ''),
			updated_at = now()
		where id = $1 and status = $2 and lifecycle_version = $3`,
		id, expectedStatus, expectedVersion, deletedBy, reason)
	if err != nil {
		return fmt.Errorf("inventory: mark account %s deleted: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("inventory: mark account %s deleted: %w", id, ErrAccountLifecycleConflict)
	}
	return nil
}

// RestoreAccountGuarded активирует существующий tombstone после успешных
// target apply + credential proof. Account остаётся с тем же id, но становится
// bare: principal и все bindings очищаются, delete metadata сбрасывается.
// Любое observed binding, появившееся между enqueue и commit, даёт conflict.
func (s *Store) RestoreAccountGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedVersion int64, credentialMode, vaultPath string) (Account, error) {
	return s.restoreAccountGuarded(ctx, q, id, expectedVersion, credentialMode, vaultPath, nil)
}

// RestorePrincipalAccountGuarded восстанавливает tombstone как аккаунт
// глобального пользователя: сохраняет principal link и общий credential.
func (s *Store) RestorePrincipalAccountGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedVersion int64, vaultPath string, principalID uuid.UUID) (Account, error) {
	return s.restoreAccountGuarded(ctx, q, id, expectedVersion,
		CredentialModeExistingVaultRef, vaultPath, &principalID)
}

func (s *Store) restoreAccountGuarded(ctx context.Context, q Querier, id uuid.UUID,
	expectedVersion int64, credentialMode, vaultPath string, principalID *uuid.UUID) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts a set
			principal_id = $5,
			credential_mode = nullif($3, ''),
			vault_path = $4,
			status = 'active',
			deleted_at = null,
			deleted_by = null,
			delete_reason = null,
			updated_at = now()
		where a.id = $1
		  and a.status = 'deleted'
		  and a.lifecycle_version = $2
		  and a.ownership = 'managed'
		  and a.kind = 'login'
		  and not exists (select 1 from bindings b where b.account_id = a.id)
		returning `+accountColumns, id, expectedVersion, credentialMode, vaultPath, principalID))
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Account{}, fmt.Errorf("inventory: restore account %s: %w", id, err)
	}
	current, getErr := s.GetAccount(ctx, q, id)
	if getErr != nil {
		return Account{}, fmt.Errorf("inventory: restore account %s: %w", id, getErr)
	}
	if checkErr := CheckAccountLifecycle(current, AccountDeleted, expectedVersion); checkErr != nil {
		return Account{}, fmt.Errorf("inventory: restore account %s: %w", id, checkErr)
	}
	return Account{}, fmt.Errorf("inventory: restore account %s: account is not an eligible bare managed login tombstone: %w",
		id, ErrAccountStatusConflict)
}

// ListAccountsByPrincipal возвращает учётные записи принципала по всем
// connections в детерминированном порядке. Аккаунты в статусе deleted
// (строки, сохранённые ради истории операций) не возвращаются —
// перечень согласован со счётчиком в principals.Store.List.
func (s *Store) ListAccountsByPrincipal(ctx context.Context, q Querier, principalID uuid.UUID) ([]Account, error) {
	rows, err := q.Query(ctx, `
		select `+accountColumns+` from accounts
		where principal_id = $1 and status <> 'deleted'
		order by connection_id, engine_identity`, principalID)
	if err != nil {
		return nil, fmt.Errorf("inventory: list accounts by principal: %w", err)
	}
	defer rows.Close()

	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: list accounts by principal: scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list accounts by principal: %w", err)
	}
	return out, nil
}

// LinkAccountPrincipal привязывает учётную запись к принципалу;
// principalID == nil снимает привязку. Возвращает обновлённую строку.
// Несуществующий account, как и несуществующий principal (нарушение FK),
// — ErrNotFound.
//
// Вместе с принципалом меняется и указатель на credential: если vault_path
// вёл в раздел ПРЕЖНЕГО принципала (общий секрет пары principal+environment,
// credential_mode=existing_vault_ref), то после отвязки или перепривязки на
// другого принципала он сбрасывается вместе с credential_mode. Иначе строка
// осталась бы с указателем на чужой общий секрет, и share/rotate выдали бы
// по ней актуальный пароль чужого принципала, открывающий все его аккаунты
// в окружении.
//
// Сброс, а не запрет операции: перепривязка — это ровно тот инструмент,
// которым исправляют неверно связанный аккаунт, и запрет заблокировал бы
// исправление. Доступ при этом не теряется молча: на целевой системе
// аккаунт продолжает работать с текущим паролем, состояние видно в API
// (пустые vault_path/credential_mode) и в audit, а POST /accounts/{id}/rotate
// одной операцией выдаёт аккаунту собственный пароль и заполняет оба поля.
//
// Условие сброса дублирует inventory.CredentialPointerForeign (Go-функцию
// из UPDATE не вызвать); менять их нужно вместе. Литерал 'principals/%'
// собран из vault.PrincipalPathPrefix, а $2 имеет тип uuid, поэтому в LIKE
// не попадают ни спецсимволы шаблона, ни внешний ввод.
func (s *Store) LinkAccountPrincipal(ctx context.Context, q Querier, accountID uuid.UUID, principalID *uuid.UUID) (Account, error) {
	const foreignPointer = `
		vault_path like '` + vault.PrincipalPathPrefix + `%'
		and ($2::uuid is null
		     or vault_path not like '` + vault.PrincipalPathPrefix + `' || $2::text || '/%')`
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts set
			principal_id = $2,
			vault_path = case when `+foreignPointer+` then '' else vault_path end,
			credential_mode = case when `+foreignPointer+` then null else credential_mode end,
			updated_at = now()
		where id = $1 and status <> 'deleted'
		returning `+accountColumns, accountID, principalID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			current, getErr := s.GetAccount(ctx, q, accountID)
			if getErr == nil && current.Status == AccountDeleted {
				return Account{}, fmt.Errorf("inventory: link account %s principal: %w", accountID, ErrAccountStatusConflict)
			}
			return Account{}, fmt.Errorf("inventory: link account %s principal: %w", accountID, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
			return Account{}, fmt.Errorf(
				"inventory: link account %s principal: referenced principal: %w", accountID, ErrNotFound)
		}
		return Account{}, fmt.Errorf("inventory: link account %s principal: %w", accountID, err)
	}
	return a, nil
}

// EnsureBindingParams — параметры upsert binding под управлением сервиса.
type EnsureBindingParams struct {
	AccountID       uuid.UUID
	PermissionID    uuid.UUID
	ScopeResourceID *uuid.UUID
	// DesiredState — целевое состояние: present или absent.
	DesiredState BindingState
	// Source — источник binding; пустое значение означает "service".
	Source    string
	ExpiresAt *time.Time
}

// EnsureBinding идемпотентно приводит binding к заданному desired state:
// создаёт строку (source/desired из params, observed unknown) либо
// обновляет desired_state/source/expires_at существующей — в том числе
// принимая под управление unmanaged binding из discovery. Возвращает
// binding и created=true для свежесозданной строки.
//
// Status выставляется по правилам ResolveBindingStatus для известного
// desired: совпадение с observed — synced, иначе (включая observed
// unknown) — pending: применение ещё впереди, drift здесь не ставится.
func (s *Store) EnsureBinding(ctx context.Context, q Querier, params EnsureBindingParams) (Binding, bool, error) {
	if params.DesiredState != BindingPresent && params.DesiredState != BindingAbsent {
		return Binding{}, false, fmt.Errorf("inventory: ensure binding: invalid desired state %q", params.DesiredState)
	}
	source := params.Source
	if source == "" {
		source = string(BindingSourceService)
	}
	var accountStatus AccountStatus
	// Row lock согласован с MarkAccountDeletedGuarded. Вызов из mutating API
	// выполняется внутри его транзакции: либо binding фиксируется раньше и
	// delete затем его удаляет, либо delete фиксирует tombstone и этот guard
	// отказывает без создания binding.
	if err := q.QueryRow(ctx, `select status from accounts where id = $1 for update`, params.AccountID).Scan(&accountStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, false, fmt.Errorf("inventory: ensure binding: account: %w", ErrNotFound)
		}
		return Binding{}, false, fmt.Errorf("inventory: ensure binding: load account status: %w", err)
	}
	if accountStatus == AccountDeleted {
		return Binding{}, false, fmt.Errorf("inventory: ensure binding: deleted account: %w", ErrAccountStatusConflict)
	}
	var assignmentKey string
	if err := q.QueryRow(ctx,
		`select assignment_key from permission_definitions where id = $1`, params.PermissionID,
	).Scan(&assignmentKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, false, fmt.Errorf("inventory: ensure binding: permission: %w", ErrNotFound)
		}
		return Binding{}, false, fmt.Errorf("inventory: ensure binding: load permission assignment key: %w", err)
	}
	if assignmentKey != "" {
		var occupiedID, occupiedPermissionID uuid.UUID
		var transitionOperationID *uuid.UUID
		var occupiedDesired *string
		var occupiedObserved, occupiedStatus string
		operationBlocksRetire := false
		err := q.QueryRow(ctx, `
			select id
			from bindings
			where account_id = $1 and assignment_key = $2`,
			params.AccountID, assignmentKey).Scan(&occupiedID)
		if err == nil {
			// FK bindings <- operations имеет ON DELETE SET NULL. Worker берёт
			// locks в порядке operation -> binding, поэтому Ensure обязан делать
			// так же: иначе retire tombstone мог образовать cross-tx deadlock.
			operationRows, lockErr := q.Query(ctx, `
				select id, status from operations where binding_id = $1 for update`, occupiedID)
			if lockErr != nil {
				return Binding{}, false, fmt.Errorf(
					"inventory: ensure binding: lock operations of assignment %s: %w", occupiedID, lockErr)
			}
			for operationRows.Next() {
				var operationID uuid.UUID
				var operationStatus string
				if scanErr := operationRows.Scan(&operationID, &operationStatus); scanErr != nil {
					operationRows.Close()
					return Binding{}, false, fmt.Errorf(
						"inventory: ensure binding: scan operations of assignment %s: %w", occupiedID, scanErr)
				}
				if operationStatus == "pending_approval" || operationStatus == "pending" ||
					operationStatus == "running" || operationStatus == "partial" {
					operationBlocksRetire = true
				}
			}
			operationRows.Close()
			if rowsErr := operationRows.Err(); rowsErr != nil {
				return Binding{}, false, fmt.Errorf(
					"inventory: ensure binding: lock operations of assignment %s: %w", occupiedID, rowsErr)
			}
			err = q.QueryRow(ctx, `
				select permission_definition_id, transition_operation_id,
				       desired_state, observed_state, status
				from bindings
				where id = $1 and account_id = $2 and assignment_key = $3
				for update`, occupiedID, params.AccountID, assignmentKey).
				Scan(&occupiedPermissionID, &transitionOperationID,
					&occupiedDesired, &occupiedObserved, &occupiedStatus)
		}
		if err == nil && transitionOperationID == nil &&
			occupiedDesired != nil && *occupiedDesired == string(BindingAbsent) &&
			occupiedObserved == string(BindingAbsent) &&
			occupiedStatus == string(BindingStatusSynced) {
			if operationBlocksRetire {
				return Binding{}, false, fmt.Errorf(
					"inventory: ensure binding: assignment tombstone %s has an unfinished operation: %w",
					occupiedID, ErrBindingTransitionConflict)
			}
			// Exact revoke завершён: историческая строка больше не представляет
			// физический slot. Удаляем её перед новым grant; FK обнулит binding_id
			// терминальных операций, а новый intent получит новый UUID и не может
			// быть затронут retry старого payload.
			tag, deleteErr := q.Exec(ctx, `
				delete from bindings
				where id = $1 and desired_state = 'absent' and observed_state = 'absent'
				  and status = 'synced' and transition_operation_id is null`, occupiedID)
			if deleteErr != nil {
				return Binding{}, false, fmt.Errorf(
					"inventory: ensure binding: retire assignment tombstone %s: %w", occupiedID, deleteErr)
			}
			if tag.RowsAffected() != 1 {
				return Binding{}, false, fmt.Errorf(
					"inventory: ensure binding: assignment tombstone %s changed: %w",
					occupiedID, ErrBindingTransitionConflict)
			}
			err = pgx.ErrNoRows
		}
		switch {
		case err == nil && transitionOperationID != nil:
			return Binding{}, false, fmt.Errorf(
				"inventory: ensure binding: assignment slot %q is owned by transition %s: %w",
				assignmentKey, *transitionOperationID, ErrBindingTransitionConflict,
			)
		case err == nil && occupiedPermissionID != params.PermissionID:
			return Binding{}, false, fmt.Errorf(
				"inventory: ensure binding: assignment slot %q is occupied by binding %s: %w",
				assignmentKey, occupiedID, ErrAssignmentOccupied,
			)
		case err != nil && !errors.Is(err, pgx.ErrNoRows):
			return Binding{}, false, fmt.Errorf("inventory: ensure binding: inspect assignment slot %q: %w", assignmentKey, err)
		}
	}

	// (xmax = 0) отличает свежую вставку от обновления существующей
	// строки: у вставленной в текущей транзакции строки xmax нулевой.
	row := q.QueryRow(ctx, `
			insert into bindings (
				account_id, permission_definition_id, scope_resource_id,
				assignment_key, source, desired_state, observed_state, status, expires_at
			) values ($1, $2, $3, $4, $5, $6, 'unknown', 'pending', $7)
			on conflict (account_id, permission_definition_id, scope_resource_id) do update set
				assignment_key = excluded.assignment_key,
				source = excluded.source,
			desired_state = excluded.desired_state,
			expires_at = excluded.expires_at,
			status = case
				when bindings.observed_state = excluded.desired_state then 'synced'
				else 'pending'
			end,
			updated_at = now()
			where bindings.transition_operation_id is null
			returning `+bindingColumns+`, (xmax = 0)`,
		params.AccountID, params.PermissionID, params.ScopeResourceID, assignmentKey,
		source, string(params.DesiredState), params.ExpiresAt,
	)

	var b Binding
	var desired *string
	var observedAttributes []byte
	var created bool
	err := row.Scan(
		&b.ID, &b.AccountID, &b.PermissionDefinitionID, &b.ScopeResourceID,
		&b.AssignmentKey, &b.ObservedPermissionDefinitionID, &observedAttributes,
		&b.Source, &desired, &b.ObservedState, &b.ObservedEffective, &b.Status,
		&b.ExpiresAt, &b.Version, &b.TransitionOperationID,
		&b.CreatedAt, &b.UpdatedAt, &created,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, false, fmt.Errorf(
				"inventory: ensure binding: binding became transition-owned: %w",
				ErrBindingTransitionConflict,
			)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && assignmentKey != "" {
			return Binding{}, false, fmt.Errorf(
				"inventory: ensure binding: assignment slot %q: %w", assignmentKey, ErrAssignmentOccupied,
			)
		}
		if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
			return Binding{}, false, fmt.Errorf(
				"inventory: ensure binding: referenced account, permission or scope: %w", ErrNotFound)
		}
		return Binding{}, false, fmt.Errorf("inventory: ensure binding: %w", err)
	}
	if desired != nil {
		state := BindingState(*desired)
		b.DesiredState = &state
	}
	b.ObservedAttributes = observedAttributes
	return b, created, nil
}

// SetBindingDesired обновляет desired state binding; status вычисляется
// через ResolveBindingStatus относительно текущего observed state.
func (s *Store) SetBindingDesired(ctx context.Context, q Querier, id uuid.UUID, desired BindingState) (Binding, error) {
	if desired != BindingPresent && desired != BindingAbsent {
		return Binding{}, fmt.Errorf("inventory: set binding %s desired: invalid state %q", id, desired)
	}
	b, err := s.GetBinding(ctx, q, id)
	if err != nil {
		return Binding{}, err
	}
	status := ResolveBindingStatus(&desired, b.ObservedState, b.ObservedEffective, b.Status)
	return s.updateBindingState(ctx, q, id, `desired_state = $2, status = $3`, string(desired), string(status))
}

// SetBindingResult записывает наблюдаемый результат применения binding;
// status вычисляется через ResolveBindingStatus относительно desired
// state строки.
//
// observed_effective сбрасывается в true вместе с состоянием: сюда попадает
// только подтверждённый результат мутации (Apply и Verify адаптера уже
// проверили целевое состояние на движке), поэтому прежняя отметка
// «право есть, но не действует» относится к состоянию ДО мутации. Без сброса
// однажды сломанный снаружи binding оставался бы в drift после штатной
// починки — до следующего discovery.
func (s *Store) SetBindingResult(ctx context.Context, q Querier, id uuid.UUID, observed BindingState) (Binding, error) {
	b, err := s.GetBinding(ctx, q, id)
	if err != nil {
		return Binding{}, err
	}
	status := ResolveBindingStatus(b.DesiredState, observed, true, b.Status)
	return s.updateBindingState(ctx, q, id,
		`observed_state = $2,
		 observed_effective = true,
		 observed_permission_definition_id = case
			when $2 = 'present' then permission_definition_id else null end,
		 observed_attributes = case
			when $2 = 'present' then coalesce(
				(select attributes from permission_definitions p where p.id = bindings.permission_definition_id),
				'{}'::jsonb)
			else '{}'::jsonb end,
		 status = $3`, string(observed), string(status))
}

// SetBindingResultExpected фиксирует результат queued access.grant/revoke
// только пока binding всё ещё представляет тот же permission/desired intent
// и не принадлежит access.replace. Это закрывает гонку API reservation с
// уже исполняющимся target side effect.
func (s *Store) SetBindingResultExpected(ctx context.Context, q Querier, id, permissionID uuid.UUID,
	desired, observed BindingState, observedAttributes json.RawMessage,
) (Binding, error) {
	if desired != BindingPresent && desired != BindingAbsent {
		return Binding{}, fmt.Errorf("inventory: set binding %s expected result: invalid desired %q", id, desired)
	}
	if observed != BindingPresent && observed != BindingAbsent {
		return Binding{}, fmt.Errorf("inventory: set binding %s expected result: invalid observed %q", id, observed)
	}
	status := ResolveBindingStatus(&desired, observed, true, BindingStatusPending)
	var pinned any
	if len(observedAttributes) > 0 {
		pinned = []byte(observedAttributes)
	}
	b, err := scanBinding(q.QueryRow(ctx, `
		update bindings set
			observed_state = $5,
			observed_effective = true,
			observed_permission_definition_id = case when $5 = 'present' then $2 else null end,
			observed_attributes = case
				when $5 = 'absent' then '{}'::jsonb
				when $6::jsonb is not null then $6::jsonb
				else coalesce((select attributes from permission_definitions p where p.id = $2), '{}'::jsonb)
			end,
			status = $4,
			updated_at = now()
		where id = $1
		  and permission_definition_id = $2
		  and desired_state = $3
		  and transition_operation_id is null
		returning `+bindingColumns,
		id, permissionID, string(desired), string(status), string(observed), pinned,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, s.bindingMutationMiss(ctx, q, id, "set expected result")
		}
		return Binding{}, fmt.Errorf("inventory: set binding %s expected result: %w", id, err)
	}
	return b, nil
}

// MarkBindingFailedExpected mirrors SetBindingResultExpected for the error
// path, so an old failed job cannot mark a newer desired intent as failed.
func (s *Store) MarkBindingFailedExpected(ctx context.Context, q Querier, id, permissionID uuid.UUID,
	desired BindingState,
) error {
	tag, err := q.Exec(ctx, `
		update bindings set status = 'failed', updated_at = now()
		where id = $1 and permission_definition_id = $2 and desired_state = $3
		  and transition_operation_id is null`, id, permissionID, string(desired))
	if err != nil {
		return fmt.Errorf("inventory: mark binding %s expected failure: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return s.bindingMutationMiss(ctx, q, id, "mark expected failure")
	}
	return nil
}

// MarkBindingFailed помечает binding как failed после ошибки применения.
// Наблюдаемое состояние не трогается: реальное положение неизвестно до
// следующего discovery.
func (s *Store) MarkBindingFailed(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx,
		`update bindings set status = 'failed', updated_at = now()
		 where id = $1 and transition_operation_id is null`, id)
	if err != nil {
		return fmt.Errorf("inventory: mark binding %s failed: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return s.bindingMutationMiss(ctx, q, id, "mark failed")
	}
	return nil
}

// updateBindingState выполняет UPDATE двух колонок состояния binding.
// set — константа вызывающего метода, не внешний ввод.
func (s *Store) updateBindingState(ctx context.Context, q Querier, id uuid.UUID, set string, args ...any) (Binding, error) {
	queryArgs := append([]any{id}, args...)
	b, err := scanBinding(q.QueryRow(ctx,
		`update bindings set `+set+`, updated_at = now()
		 where id = $1 and transition_operation_id is null returning `+bindingColumns,
		queryArgs...,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, s.bindingMutationMiss(ctx, q, id, "update")
		}
		return Binding{}, fmt.Errorf("inventory: update binding %s: %w", id, err)
	}
	return b, nil
}

func (s *Store) bindingMutationMiss(ctx context.Context, q Querier, id uuid.UUID, action string) error {
	current, err := s.GetBinding(ctx, q, id)
	switch {
	case err == nil && current.TransitionOperationID != nil:
		return fmt.Errorf("inventory: %s binding %s: owned by transition %s: %w",
			action, id, *current.TransitionOperationID, ErrBindingTransitionConflict)
	case err == nil:
		return fmt.Errorf("inventory: %s binding %s: state changed: %w",
			action, id, ErrBindingTransitionConflict)
	case errors.Is(err, ErrNotFound):
		return fmt.Errorf("inventory: %s binding %s: %w", action, id, ErrNotFound)
	default:
		return fmt.Errorf("inventory: %s binding %s: inspect miss: %w", action, id, err)
	}
}

// SetAccountCredentialVersion закрепляет якорь: версию секрета Vault,
// которую grantor реально применил к целевой системе.
//
// Вызывается в той же транзакции, что и фиксация успеха ротации: якорь без
// применённого пароля был бы ложью, а применённый пароль без якоря вернул бы
// нас к прежнему состоянию — расхождение с Vault некому заметить.
// Наблюдаемая версия сбрасывается к тому же значению: сразу после ротации
// Vault и таргет заведомо согласованы, и оставшееся расхождение от прошлой
// правки должно погаснуть.
func (s *Store) SetAccountCredentialVersion(ctx context.Context, q Querier, id uuid.UUID, version int) error {
	if version <= 0 {
		return fmt.Errorf("inventory: set account %s credential version: version must be positive", id)
	}
	if _, err := q.Exec(ctx, `
		update accounts set
			credential_version = $2,
			credential_observed_version = $2,
			credential_checked_at = now(),
			updated_at = now()
		where id = $1`, id, version); err != nil {
		return fmt.Errorf("inventory: set account %s credential version: %w", id, err)
	}
	return nil
}

// RestoreBindingDesired возвращает binding к прежнему желаемому состоянию;
// nil означает unmanaged (desired NULL). Используется откатом отклонённой
// операции: обычный SetBindingDesired не умеет вернуть строку в unmanaged, а
// именно им она и была до выдачи через adopt-путь.
func (s *Store) RestoreBindingDesired(ctx context.Context, q Querier, id uuid.UUID, desired *BindingState) (Binding, error) {
	if desired != nil {
		return s.SetBindingDesired(ctx, q, id, *desired)
	}
	b, err := s.GetBinding(ctx, q, id)
	if err != nil {
		return Binding{}, err
	}
	status := ResolveBindingStatus(nil, b.ObservedState, b.ObservedEffective, b.Status)
	return s.updateBindingState(ctx, q, id, `desired_state = null, status = $2`, string(status))
}

// DeleteUnappliedBinding удаляет binding, к которому на целевой системе ещё
// не применялось ничего (observed_state = 'unknown'). Возвращает false, если
// строки нет или к ней уже есть наблюдение.
//
// Нужен откату отклонённой выдачи: строку создала сама выдача, и оставлять её
// с desired absent значило бы показывать несуществующее право как «отозвано».
func (s *Store) DeleteUnappliedBinding(ctx context.Context, q Querier, id uuid.UUID) (bool, error) {
	tag, err := q.Exec(ctx,
		`delete from bindings
		 where id = $1 and observed_state = 'unknown' and transition_operation_id is null`, id)
	if err != nil {
		return false, fmt.Errorf("inventory: delete unapplied binding %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		current, getErr := s.GetBinding(ctx, q, id)
		if getErr == nil && current.TransitionOperationID != nil {
			return false, fmt.Errorf("inventory: delete unapplied binding %s: %w", id, ErrBindingTransitionConflict)
		}
	}
	return tag.RowsAffected() > 0, nil
}

// CreatePlannedResourceParams — параметры резервирования ресурса, который
// grantor собирается создать в целевой системе.
type CreatePlannedResourceParams struct {
	ConnectionID  uuid.UUID
	Kind          string
	ExternalID    string
	Name          string
	CanonicalPath string
}

// CreatePlannedResource заводит строку ресурса в статусе planned до того, как
// он появится в целевой системе. Строка резервирует (kind, external_id) в
// пределах подключения: повторный запрос получает ErrAlreadyExists вместо
// второй операции создания. Discovery такую строку не помечает missing —
// planned существует именно как desired state (см. markMissingResources).
func (s *Store) CreatePlannedResource(ctx context.Context, q Querier, params CreatePlannedResourceParams) (Resource, error) {
	if params.ExternalID == "" || params.Kind == "" {
		return Resource{}, errors.New("inventory: create planned resource: kind and external id are required")
	}
	r, err := scanResource(q.QueryRow(ctx, `
		insert into resources (
			connection_id, kind, external_id, name, canonical_path,
			attributes, fingerprint, status, ownership
		) values ($1, $2, $3, $4, $5, '{}'::jsonb, '', 'planned', 'managed')
		returning `+resourceColumns,
		params.ConnectionID, params.Kind, params.ExternalID, params.Name, params.CanonicalPath,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				return Resource{}, fmt.Errorf(
					"inventory: create planned resource: %s %q already exists in connection %s: %w",
					params.Kind, params.Name, params.ConnectionID, ErrAlreadyExists)
			case pgForeignKeyViolation:
				return Resource{}, fmt.Errorf(
					"inventory: create planned resource: connection %s: %w",
					params.ConnectionID, ErrNotFound)
			}
		}
		return Resource{}, fmt.Errorf("inventory: create planned resource: %w", err)
	}
	return r, nil
}

// MarkResourceObserved переводит planned-ресурс в observed после
// подтверждённого создания. Guarded по статусу: наблюдение, пришедшее
// discovery раньше, не откатывается.
func (s *Store) MarkResourceObserved(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `
		update resources set status = 'observed', observed_at = now(), updated_at = now()
		where id = $1 and status = 'planned'`, id)
	if err != nil {
		return fmt.Errorf("inventory: mark resource %s observed: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		// Строка уже наблюдается (discovery опередил) — это успех, а не сбой.
		return nil
	}
	return nil
}
