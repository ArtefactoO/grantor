package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrNotFound возвращается, когда подключение с указанным id не
	// существует.
	ErrNotFound = errors.New("connections: connection not found")
	// ErrInvalidTransition возвращается при попытке перехода, которого
	// нет в карте допустимых переходов (см. CanTransition).
	ErrInvalidTransition = errors.New("connections: invalid status transition")
	// ErrStatusConflict возвращается, когда переход допустим, но текущий
	// статус строки в базе не совпал с ожидаемым from (конкурентное
	// изменение). Вызывающий может перечитать подключение и решить заново.
	ErrStatusConflict = errors.New("connections: status conflict")
	// ErrVersionConflict возвращается, когда updated_at строки не совпал с
	// версией, которую видел клиент PATCH. Вызывающий должен перечитать
	// connection и не пытаться молча затереть конкурентное изменение.
	ErrVersionConflict = errors.New("connections: version conflict")
)

// Querier — минимальный контракт выполнения запросов pgx; ему
// удовлетворяют и *pgxpool.Pool, и pgx.Tx. Интерфейс объявлен локально
// (а не импортирован из core/operations) сознательно: пакеты ядра не
// зависят друг от друга ради трёх методов, а структурная типизация Go
// делает локальные копии взаимозаменяемыми для вызывающего.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store — доступ к таблице connections. Не хранит соединение: Querier
// передаётся в каждый метод, чтобы вызывающий управлял транзакциями.
// Zero value полностью работоспособен.
//
// # Колонка capabilities
//
// capabilities — производное поле, а не пользовательский ввод: набор
// операций, доступных на ЭТОМ подключении. Store — единственный писатель
// колонки на рабочих путях (Create, PatchCAS, SetDiscoveryResult) и приводит
// любой переданный набор к эффективному через EffectiveCapabilities. Так
// engine-wide манифест не может просочиться в UI и API-гварды в обход
// per-connection сужения (kafka: PLAIN-подключение не заявляет SCRAM-
// lifecycle, кластер без ACL-авторизатора — grant/revoke), и не важно, какой
// из писателей строку обновил.
//
// Исключение — Update: полная замена всех редактируемых полей «как передано»,
// включая capabilities. Он используется обслуживающим кодом и тестами, чтобы
// собрать нужное состояние строки явно, и сужения не выполняет.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// connectionColumns — единый список колонок для всех RETURNING/SELECT,
// согласованный со scanConnection.
const connectionColumns = `id, display_name, engine, environment, tags, endpoints,
	execution_mode, tls_config, admin_credential_mode, vault_admin_path, auth_mode,
	capabilities, discovery_config, status, server_version, topology,
	last_discovery_at, created_at, updated_at`

// CreateParams — параметры создания подключения. Подключение всегда
// создаётся в статусе draft. Пустые ExecutionMode и AdminCredentialMode
// заменяются значениями по умолчанию схемы (direct, provided); nil
// jsonb-поля — пустыми объектами.
//
// Capabilities — engine-wide манифест adapter; store сужает его под саму
// строку подключения (см. EffectiveCapabilities и doc-комментарий Store).
type CreateParams struct {
	// ID is a server-reserved identity for durable onboarding. Nil retains
	// the ordinary database-generated identity; HTTP clients never choose it.
	ID                  *uuid.UUID
	DisplayName         string
	Engine              string
	AuthMode            string
	Environment         string
	Tags                []string
	Endpoints           []string
	ExecutionMode       string
	TLSConfig           json.RawMessage
	AdminCredentialMode string
	VaultAdminPath      string
	Capabilities        []string
	DiscoveryConfig     json.RawMessage
}

// Create создаёт подключение в статусе draft и возвращает созданную
// строку.
func (s *Store) Create(ctx context.Context, q Querier, params CreateParams) (Connection, error) {
	if params.DisplayName == "" {
		return Connection{}, errors.New("connections: create: display name is required")
	}
	if params.Engine == "" {
		return Connection{}, errors.New("connections: create: engine is required")
	}
	executionMode := params.ExecutionMode
	if executionMode == "" {
		executionMode = ExecutionModeDirect
	}
	// Валидация до SQL: CHECK схемы отбил бы неизвестный режим и сам, но
	// store обязан отвечать понятной ошибкой, а не raw SQLSTATE.
	if !ValidExecutionMode(executionMode) {
		return Connection{}, fmt.Errorf(
			"connections: create: unknown execution mode %q (supported: %s, %s)",
			executionMode, ExecutionModeDirect, ExecutionModeConnector)
	}
	authMode := params.AuthMode
	if authMode == "" {
		authMode = "password"
	}
	if authMode != "password" && (authMode != "none" || params.Engine != "redis" || params.VaultAdminPath != "") {
		return Connection{}, errors.New("connections: invalid authentication mode")
	}
	credentialMode := params.AdminCredentialMode
	if credentialMode == "" {
		credentialMode = "provided"
	}

	tags, err := marshalStringSlice(params.Tags)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: create: marshal tags: %w", err)
	}
	endpoints, err := marshalStringSlice(params.Endpoints)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: create: marshal endpoints: %w", err)
	}
	// Сужение до создания строки: подключение сразу заявляет только то, что на
	// нём выполнимо (topology ещё нет — она появится после discovery).
	capabilities, err := marshalStringSlice(EffectiveCapabilities(Connection{
		Engine:          params.Engine,
		AuthMode:        authMode,
		Endpoints:       params.Endpoints,
		TLSConfig:       params.TLSConfig,
		DiscoveryConfig: params.DiscoveryConfig,
	}, params.Capabilities))
	if err != nil {
		return Connection{}, fmt.Errorf("connections: create: marshal capabilities: %w", err)
	}

	conn, err := scanConnection(q.QueryRow(ctx, `
		insert into connections (
			id, display_name, engine, environment, tags, endpoints, execution_mode,
			tls_config, admin_credential_mode, vault_admin_path, auth_mode,
			capabilities, discovery_config
		) values (coalesce($12::uuid, gen_random_uuid()), $1, $2, $3, $4, $5, $6, $7, $8, $9, $13, $10, $11)
		returning `+connectionColumns,
		params.DisplayName, params.Engine, params.Environment,
		tags, endpoints, executionMode,
		jsonObjectOrEmpty(params.TLSConfig), credentialMode, params.VaultAdminPath,
		capabilities, jsonObjectOrEmpty(params.DiscoveryConfig),
		params.ID, authMode,
	))
	if err != nil {
		return Connection{}, fmt.Errorf("connections: create: %w", err)
	}
	return conn, nil
}

// Get возвращает подключение по id. Если его нет — ErrNotFound.
func (s *Store) Get(ctx context.Context, q Querier, id uuid.UUID) (Connection, error) {
	conn, err := scanConnection(q.QueryRow(ctx,
		`select `+connectionColumns+` from connections where id = $1`, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Connection{}, fmt.Errorf("connections: get %s: %w", id, ErrNotFound)
		}
		return Connection{}, fmt.Errorf("connections: get %s: %w", id, err)
	}
	return conn, nil
}

// GetEnvironment avoids loading the discovery snapshot for scope checks.
func (s *Store) GetEnvironment(ctx context.Context, q Querier, id uuid.UUID) (string, error) {
	var environment string
	if err := q.QueryRow(ctx, `select environment from connections where id=$1`, id).Scan(&environment); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("connections: get environment %s: %w", id, ErrNotFound)
		}
		return "", fmt.Errorf("connections: get environment %s: %w", id, err)
	}
	return environment, nil
}

// List возвращает все подключения в порядке создания.
func (s *Store) List(ctx context.Context, q Querier) ([]Connection, error) {
	rows, err := q.Query(ctx,
		`select `+connectionColumns+` from connections order by created_at, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("connections: list: %w", err)
	}
	defer rows.Close()

	var conns []Connection
	for rows.Next() {
		conn, err := scanConnection(rows)
		if err != nil {
			return nil, fmt.Errorf("connections: list: scan: %w", err)
		}
		conns = append(conns, conn)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connections: list: %w", err)
	}
	return conns, nil
}

// UpdateParams — редактируемые администратором поля подключения.
// Семантика полной замены: каждое поле записывается как есть (nil слайсы
// становятся пустыми jsonb-массивами, nil jsonb — пустыми объектами).
// Ожидаемый паттерн вызова: Get, изменение полей, Update.
type UpdateParams struct {
	DisplayName     string
	Environment     string
	Tags            []string
	Endpoints       []string
	TLSConfig       json.RawMessage
	DiscoveryConfig json.RawMessage
	Capabilities    []string
}

// PatchParams — уже объединённые с текущей строкой редактируемые поля PATCH.
// ExpectedUpdatedAt и ExpectedStatus образуют compare-and-swap. Operational
// включает специальный reconfigure-переход: status становится discovering,
// а server_version/topology/last_discovery_at очищаются атомарно с полями.
//
// Capabilities в параметрах намеренно отсутствуют: они не пользовательский
// ввод. Но и неизменными они не остаются — PatchCAS пересчитывает их из
// патченного tls_config/discovery_config и пишет в том же UPDATE (иначе
// подключение, переведённое, например, на PLAIN, продолжало бы заявлять
// операции, которые упадут на Apply).
type PatchParams struct {
	DisplayName       string
	Environment       string
	Tags              []string
	Endpoints         []string
	TLSConfig         json.RawMessage
	DiscoveryConfig   json.RawMessage
	ExpectedUpdatedAt time.Time
	ExpectedStatus    Status
	Operational       bool
}

// PatchCAS применяет строгий connection PATCH с compare-and-swap по
// updated_at/status. Per-connection advisory lock должен быть уже взят
// вызывающим в той же транзакции: store принимает общий Querier, поэтому не
// может безопасно создавать границы транзакции сам.
//
// Вместе с полями пересчитываются capabilities: их эффективный набор зависит
// от tls_config/discovery_config, которые этот патч и меняет. Текущая строка
// читается той же транзакцией под тем же advisory lock — engine и старый
// набор нужны как исходные данные, а CAS-гарды остаются на самом UPDATE.
// Operational-патч сбрасывает topology, поэтому и сужение по наблюдаемому
// состоянию кластера снимается до следующего discovery.
func (s *Store) PatchCAS(ctx context.Context, q Querier, id uuid.UUID, params PatchParams) (Connection, error) {
	if params.DisplayName == "" {
		return Connection{}, fmt.Errorf("connections: patch %s: display name is required", id)
	}
	if params.ExpectedUpdatedAt.IsZero() {
		return Connection{}, fmt.Errorf("connections: patch %s: expected updated_at is required", id)
	}
	if params.Operational {
		if !CanReconfigure(params.ExpectedStatus) {
			return Connection{}, fmt.Errorf("connections: patch %s: reconfigure from %q: %w",
				id, params.ExpectedStatus, ErrStatusConflict)
		}
	} else if !CanEditMetadata(params.ExpectedStatus) {
		return Connection{}, fmt.Errorf("connections: patch %s: metadata edit from %q: %w",
			id, params.ExpectedStatus, ErrStatusConflict)
	}

	tags, err := marshalStringSlice(params.Tags)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: patch %s: marshal tags: %w", id, err)
	}
	endpoints, err := marshalStringSlice(params.Endpoints)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: patch %s: marshal endpoints: %w", id, err)
	}

	current, err := s.Get(ctx, q, id)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: patch %s: %w", id, err)
	}
	patched := Connection{
		Engine:          current.Engine,
		Endpoints:       params.Endpoints,
		TLSConfig:       params.TLSConfig,
		DiscoveryConfig: params.DiscoveryConfig,
		Topology:        current.Topology,
	}
	if params.Operational {
		patched.Topology = nil
	}
	capabilities, err := marshalStringSlice(EffectiveCapabilities(patched, current.Capabilities))
	if err != nil {
		return Connection{}, fmt.Errorf("connections: patch %s: marshal capabilities: %w", id, err)
	}

	var query string
	if params.Operational {
		query = `
			update connections set
				display_name = $2,
				environment = $3,
				tags = $4,
				endpoints = $5,
				tls_config = $6,
				discovery_config = $7,
				capabilities = $10,
				status = 'discovering',
				server_version = '',
				topology = '{}'::jsonb,
				last_discovery_at = null,
				updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
			where id = $1 and updated_at = $8 and status = $9
			returning ` + connectionColumns
	} else {
		query = `
			update connections set
				display_name = $2,
				environment = $3,
				tags = $4,
				endpoints = $5,
				tls_config = $6,
				discovery_config = $7,
				capabilities = $10,
				updated_at = greatest(clock_timestamp(), updated_at + interval '1 microsecond')
			where id = $1 and updated_at = $8 and status = $9
			returning ` + connectionColumns
	}

	conn, err := scanConnection(q.QueryRow(ctx, query,
		id, params.DisplayName, params.Environment, tags, endpoints,
		jsonObjectOrEmpty(params.TLSConfig), jsonObjectOrEmpty(params.DiscoveryConfig),
		params.ExpectedUpdatedAt, params.ExpectedStatus, capabilities,
	))
	if err == nil {
		return conn, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, fmt.Errorf("connections: patch %s: %w", id, err)
	}

	// Guard не сработал: строку перечитываем заново, потому что между чтением
	// выше и UPDATE её мог изменить кто-то ещё.
	latest, getErr := s.Get(ctx, q, id)
	if getErr != nil {
		return Connection{}, fmt.Errorf("connections: patch %s: %w", id, getErr)
	}
	if !latest.UpdatedAt.Equal(params.ExpectedUpdatedAt) {
		return Connection{}, fmt.Errorf("connections: patch %s: current updated_at %s: %w",
			id, latest.UpdatedAt.UTC().Format(time.RFC3339Nano), ErrVersionConflict)
	}
	return Connection{}, fmt.Errorf("connections: patch %s: current status %q: %w",
		id, latest.Status, ErrStatusConflict)
}

// Update перезаписывает редактируемые поля подключения и возвращает
// обновлённую строку. Если подключения нет — ErrNotFound.
//
// В отличие от Create/PatchCAS/SetDiscoveryResult, capabilities пишутся как
// переданы, без сужения: это низкоуровневая полная замена полей для
// обслуживания и тестов, где состояние строки задаётся явно.
func (s *Store) Update(ctx context.Context, q Querier, id uuid.UUID, params UpdateParams) (Connection, error) {
	if params.DisplayName == "" {
		return Connection{}, fmt.Errorf("connections: update %s: display name is required", id)
	}
	tags, err := marshalStringSlice(params.Tags)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: update %s: marshal tags: %w", id, err)
	}
	endpoints, err := marshalStringSlice(params.Endpoints)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: update %s: marshal endpoints: %w", id, err)
	}
	capabilities, err := marshalStringSlice(params.Capabilities)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: update %s: marshal capabilities: %w", id, err)
	}

	conn, err := scanConnection(q.QueryRow(ctx, `
		update connections set
			display_name = $2,
			environment = $3,
			tags = $4,
			endpoints = $5,
			tls_config = $6,
			discovery_config = $7,
			capabilities = $8,
			updated_at = now()
		where id = $1
		returning `+connectionColumns,
		id, params.DisplayName, params.Environment, tags, endpoints,
		jsonObjectOrEmpty(params.TLSConfig), jsonObjectOrEmpty(params.DiscoveryConfig),
		capabilities,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Connection{}, fmt.Errorf("connections: update %s: %w", id, ErrNotFound)
		}
		return Connection{}, fmt.Errorf("connections: update %s: %w", id, err)
	}
	return conn, nil
}

// Transition атомарно переводит подключение из статуса from в to.
//
// Переход валидируется по CanTransition (ErrInvalidTransition), затем
// выполняется UPDATE с guard `status = from`: если строка не обновилась,
// подключение либо не существует (ErrNotFound), либо его статус изменил
// кто-то другой (ErrStatusConflict).
func (s *Store) Transition(ctx context.Context, q Querier, id uuid.UUID, from, to Status) (Connection, error) {
	if !CanTransition(from, to) {
		return Connection{}, fmt.Errorf("connections: transition %s: %q -> %q: %w",
			id, from, to, ErrInvalidTransition)
	}

	conn, err := scanConnection(q.QueryRow(ctx, `
		update connections set
			status = $2,
			updated_at = now()
		where id = $1 and status = $3
		returning `+connectionColumns,
		id, to, from,
	))
	if err == nil {
		return conn, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, fmt.Errorf("connections: transition %s: %q -> %q: %w", id, from, to, err)
	}

	// Guard не сработал: различаем отсутствие строки и конфликт статуса.
	current, getErr := s.Get(ctx, q, id)
	if getErr != nil {
		return Connection{}, fmt.Errorf("connections: transition %s: %q -> %q: %w", id, from, to, getErr)
	}
	return Connection{}, fmt.Errorf("connections: transition %s: %q -> %q: current status %q: %w",
		id, from, to, current.Status, ErrStatusConflict)
}

// Delete удаляет строку connection и возвращает управление вызывающему.
//
// Операция затрагивает ТОЛЬКО metadata database grantor: удаление строки
// connections через FK-каскад схемы (db/migrations/00001_core_schema.sql)
// удаляет resources / accounts / bindings / permission_definitions этого
// подключения и обнуляет connection_id в operations (ON DELETE SET NULL);
// audit_events переживают удаление (FK нет). Целевой кластер (PostgreSQL /
// RabbitMQ / ...) при этом НЕ трогается: никаких adapter-вызовов, revoke,
// drop user или изменения ACL — это чистое удаление метаданных. Managed-
// аккаунты, созданные grantor в целевой системе, после удаления остаются
// там осиротевшими; их проверка/предупреждение — забота вызывающего
// (см. deleteConnection в internal/api), а не этого метода.
//
// Если подключения с указанным id нет — ErrNotFound (идемпотентность:
// повторное удаление отвечает 404).
func (s *Store) Delete(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `delete from connections where id = $1`, id)
	if err != nil {
		return fmt.Errorf("connections: delete %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("connections: delete %s: %w", id, ErrNotFound)
	}
	return nil
}

// SetDiscoveryResult записывает итог успешного discovery: server version,
// topology, эффективные adapter capabilities и момент наблюдения
// (last_discovery_at). Статус подключения не меняется — переходами управляет
// вызывающий через Transition. Nil topology записывается пустым объектом.
// Если подключения нет — ErrNotFound.
//
// capabilities — engine-wide манифест adapter (верхняя граница). Записывается
// не он, а его сужение под это подключение: конфигурация подключения плюс
// СВЕЖАЯ topology этого же snapshot, в которой adapter мог сообщить о
// рантайм-ограничении цели (kafka: выключенный ACL-авторизатор). Discovery —
// единственный момент, когда такое наблюдение появляется, поэтому сужение
// выполняется здесь, атомарно с самим результатом; в connector-режиме это
// одинаково верно — сужение считается в control plane, а не на агенте.
func (s *Store) SetDiscoveryResult(ctx context.Context, q Querier, id uuid.UUID, serverVersion string, topology []byte, capabilities []string, at time.Time) error {
	if len(topology) == 0 {
		topology = []byte("{}")
	}
	conn, err := s.Get(ctx, q, id)
	if err != nil {
		return fmt.Errorf("connections: set discovery result %s: %w", id, err)
	}
	conn.Topology = topology
	capabilitiesJSON, err := marshalStringSlice(EffectiveCapabilities(conn, capabilities))
	if err != nil {
		return fmt.Errorf("connections: set discovery result %s: marshal capabilities: %w", id, err)
	}
	tag, err := q.Exec(ctx, `
		update connections set
			server_version = $2,
			topology = $3,
			capabilities = $4,
			last_discovery_at = $5,
			updated_at = now()
		where id = $1`,
		id, serverVersion, topology, capabilitiesJSON, at,
	)
	if err != nil {
		return fmt.Errorf("connections: set discovery result %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("connections: set discovery result %s: %w", id, ErrNotFound)
	}
	return nil
}

// marshalStringSlice кодирует срез строк в jsonb-массив; nil становится
// пустым массивом, чтобы колонка никогда не получала SQL NULL.
func marshalStringSlice(v []string) ([]byte, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// jsonObjectOrEmpty возвращает переданный jsonb-документ или пустой
// объект, если документ не задан.
func jsonObjectOrEmpty(v json.RawMessage) []byte {
	if len(v) == 0 {
		return []byte("{}")
	}
	return v
}

// scanConnection читает одну строку connections в Connection. Порядок
// полей обязан совпадать с connectionColumns.
func scanConnection(row pgx.Row) (Connection, error) {
	var c Connection
	var tags, endpoints, capabilities, tlsConfig, discoveryConfig, topology []byte
	err := row.Scan(
		&c.ID, &c.DisplayName, &c.Engine, &c.Environment, &tags, &endpoints,
		&c.ExecutionMode, &tlsConfig, &c.AdminCredentialMode, &c.VaultAdminPath, &c.AuthMode,
		&capabilities, &discoveryConfig, &c.Status, &c.ServerVersion, &topology,
		&c.LastDiscoveryAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return Connection{}, err
	}
	if err := json.Unmarshal(tags, &c.Tags); err != nil {
		return Connection{}, fmt.Errorf("unmarshal tags: %w", err)
	}
	if err := json.Unmarshal(endpoints, &c.Endpoints); err != nil {
		return Connection{}, fmt.Errorf("unmarshal endpoints: %w", err)
	}
	if err := json.Unmarshal(capabilities, &c.Capabilities); err != nil {
		return Connection{}, fmt.Errorf("unmarshal capabilities: %w", err)
	}
	c.TLSConfig = tlsConfig
	c.DiscoveryConfig = discoveryConfig
	c.Topology = topology
	return c, nil
}
