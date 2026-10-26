package inventory

// Отчёт о расхождениях (drift findings) и принятие unmanaged bindings
// под управление для раздела «Дрифт» UI (docs/architecture.md, раздел
// 20.7). Условия выборок обязаны совпадать со счётчиками DriftSummary в
// store.go; семантика unmanaged/drift описана в doc-комментарии пакета.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrAlreadyManaged возвращается при попытке adopt binding, у которого
// desired state уже задан (он уже под управлением grantor).
var (
	ErrAlreadyManaged  = errors.New("inventory: binding is already managed")
	ErrBindingReadOnly = errors.New("inventory: binding is read-only and cannot be adopted")
	// ErrBindingObservationMismatch запрещает принимать exclusive slot, пока
	// actual permission не сопоставлен выбранному template exact и effective.
	ErrBindingObservationMismatch = errors.New("inventory: binding observation does not match assignment")
)

func BindingManagementEligible(b Binding) bool {
	var observation struct {
		Eligible *bool `json:"managed_binding_eligible"`
	}
	if json.Unmarshal(b.ObservedAttributes, &observation) != nil {
		return true
	}
	return observation.Eligible == nil || *observation.Eligible
}

func exclusiveObservationMatches(b Binding) bool {
	return b.TransitionOperationID == nil && (b.AssignmentKey == "" ||
		(b.ObservedState == BindingPresent && b.ObservedEffective &&
			b.ObservedPermissionDefinitionID != nil &&
			*b.ObservedPermissionDefinitionID == b.PermissionDefinitionID))
}

// DriftFindings возвращает расхождения desired/observed state для UI:
// bindings в статусе drift или failed, обнаруженные внешние bindings без
// принятого решения и managed-ресурсы, исчезнувшие из целевой системы.
// connectionID == nil — по всем connections; для bindings фильтр идёт
// через accounts.connection_id. Порядок детерминированный: сначала
// binding_drift, затем unmanaged_binding, missing_resource и
// missing_account; внутри вида — по connection, идентичности аккаунта
// (для ресурсов — имени) и id.
func (s *Store) DriftFindings(ctx context.Context, q Querier, connectionID *uuid.UUID) ([]DriftFinding, error) {
	// failed — то же доказанное расхождение, что и drift (применение упало,
	// желаемое состояние не достигнуто), и до этой выборки оно не было
	// видно нигде: оператор узнавал о поломке только при повторной выдаче.
	drift, err := s.listBindingFindings(ctx, q, DriftKindBindingDrift,
		`b.status in ('drift', 'failed')`, connectionID)
	if err != nil {
		return nil, err
	}
	unmanaged, err := s.listBindingFindings(ctx, q, DriftKindUnmanagedBinding,
		`b.source = 'external' and b.desired_state is null and b.observed_state = 'present'`, connectionID)
	if err != nil {
		return nil, err
	}
	missing, err := s.listMissingResourceFindings(ctx, q, connectionID)
	if err != nil {
		return nil, err
	}
	missingAccounts, err := s.listMissingAccountFindings(ctx, q, connectionID)
	if err != nil {
		return nil, err
	}
	credentials, err := s.listCredentialDivergedFindings(ctx, q, connectionID)
	if err != nil {
		return nil, err
	}

	findings := make([]DriftFinding, 0,
		len(drift)+len(unmanaged)+len(missing)+len(missingAccounts)+len(credentials))
	findings = append(findings, drift...)
	findings = append(findings, unmanaged...)
	findings = append(findings, missing...)
	findings = append(findings, missingAccounts...)
	findings = append(findings, credentials...)
	return findings, nil
}

// listCredentialDivergedFindings возвращает аккаунты, чей секрет в Vault
// переписали мимо grantor: наблюдаемая версия опередила применённую к
// целевой системе (accounts.credential_version, миграция 00017).
//
// Это расхождение принципиально иного рода, чем остальные: объекты и
// bindings на месте, ломается именно выдача учётных данных — оператор
// получает пароль, которого в целевой системе нет. Поэтому оно вынесено
// отдельным видом, а не смешано с missing_account.
func (s *Store) listCredentialDivergedFindings(ctx context.Context, q Querier, connectionID *uuid.UUID) ([]DriftFinding, error) {
	rows, err := q.Query(ctx, `
		select connection_id, id, engine_identity,
		       credential_version, credential_observed_version
		from accounts
		where ownership = 'managed' and status <> 'deleted'
		  and credential_version > 0
		  and credential_observed_version > credential_version
		  and ($1::uuid is null or connection_id = $1)
		order by connection_id, engine_identity, id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", DriftKindCredentialDiverged, err)
	}
	defer rows.Close()

	var out []DriftFinding
	for rows.Next() {
		f := DriftFinding{Kind: DriftKindCredentialDiverged}
		var accountID uuid.UUID
		var applied, observed int
		if err := rows.Scan(&f.ConnectionID, &accountID, &f.AccountIdentity, &applied, &observed); err != nil {
			return nil, fmt.Errorf("inventory: drift findings %s: scan: %w", DriftKindCredentialDiverged, err)
		}
		f.AccountID = &accountID
		f.Detail = fmt.Sprintf(
			"пароль изменён мимо grantor: применена версия %d, в Vault сейчас %d — "+
				"выданный пароль может не работать, восстановит ротация",
			applied, observed)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", DriftKindCredentialDiverged, err)
	}
	return out, nil
}

// listMissingAccountFindings возвращает findings по managed-аккаунтам,
// которых нет в целевой системе: discovery не нашёл их (missing) либо их
// account.create так и не подтвердился (provisioning). Оба случая — одно
// расхождение для оператора: control plane считает учётку своей, а
// доступа по ней не существует. Detail различает происхождение, чтобы
// было понятно, чинится это повтором выдачи доступа или расследованием
// внешнего удаления.
func (s *Store) listMissingAccountFindings(ctx context.Context, q Querier, connectionID *uuid.UUID) ([]DriftFinding, error) {
	rows, err := q.Query(ctx, `
		select connection_id, id, engine_identity, status
		from accounts
		where ownership = 'managed' and status in ('missing', 'provisioning')
		  and ($1::uuid is null or connection_id = $1)
		order by connection_id, engine_identity, id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", DriftKindMissingAccount, err)
	}
	defer rows.Close()

	var out []DriftFinding
	for rows.Next() {
		f := DriftFinding{Kind: DriftKindMissingAccount}
		var accountID uuid.UUID
		var status AccountStatus
		if err := rows.Scan(&f.ConnectionID, &accountID, &f.AccountIdentity, &status); err != nil {
			return nil, fmt.Errorf("inventory: drift findings %s: scan: %w", DriftKindMissingAccount, err)
		}
		f.AccountID = &accountID
		if status == AccountProvisioning {
			f.Detail = "учётная запись не создана в целевой системе (провижининг не завершён)"
		} else {
			f.Detail = "managed-аккаунт исчез из целевой системы"
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", DriftKindMissingAccount, err)
	}
	return out, nil
}

// listBindingFindings выполняет выборку binding-расхождений по условию.
// where — константа вызывающего метода, не внешний ввод. desired_state
// в Detail коалесцируется в unknown только для устойчивости: у drift он
// задан всегда, для unmanaged Detail не использует состояния.
func (s *Store) listBindingFindings(ctx context.Context, q Querier, kind, where string, connectionID *uuid.UUID) ([]DriftFinding, error) {
	rows, err := q.Query(ctx, `
		select a.connection_id, b.id, b.account_id, b.permission_definition_id,
		       b.scope_resource_id, a.engine_identity, p.name,
		       coalesce(r.name, ''),
		       coalesce(b.desired_state, 'unknown'), b.observed_state, b.observed_effective
		from bindings b
		join accounts a on a.id = b.account_id
		join permission_definitions p on p.id = b.permission_definition_id
		left join resources r on r.id = b.scope_resource_id
		where `+where+`
		  and ($1::uuid is null or a.connection_id = $1)
		order by a.connection_id, a.engine_identity, p.name, b.id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", kind, err)
	}
	defer rows.Close()

	var out []DriftFinding
	for rows.Next() {
		f := DriftFinding{Kind: kind}
		var bindingID, accountID, permissionID uuid.UUID
		var desired, observed string
		var effective bool
		if err := rows.Scan(
			&f.ConnectionID, &bindingID, &accountID, &permissionID,
			&f.ResourceID, &f.AccountIdentity, &f.PermissionName,
			&f.ResourceName, &desired, &observed, &effective,
		); err != nil {
			return nil, fmt.Errorf("inventory: drift findings %s: scan: %w", kind, err)
		}
		f.BindingID = &bindingID
		f.AccountID = &accountID
		f.PermissionID = &permissionID
		switch {
		case kind == DriftKindUnmanagedBinding:
			f.Detail = "обнаружен внешний грант"
		case !effective && observed == string(BindingPresent):
			// Отдельный текст: «право есть, но не работает» и «права нет» —
			// разные ситуации, и чинятся они по-разному. Без объяснения
			// оператор видел бы дрифт там, где грант на месте.
			f.Detail = "право выдано, но не действует: роль не входит в набор " +
				"по умолчанию и доступа не даёт"
		default:
			// Detail — пользовательский текст ответа API, а не сообщение об
			// ошибке: язык здесь единый с остальными findings (русский).
			// Сами desired/observed остаются идентификаторами состояний
			// (present/absent/unknown) и не переводятся.
			f.Detail = fmt.Sprintf("желаемое состояние %s, наблюдаемое %s", desired, observed)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", kind, err)
	}
	return out, nil
}

// listMissingResourceFindings возвращает findings по managed-ресурсам в
// статусе missing.
func (s *Store) listMissingResourceFindings(ctx context.Context, q Querier, connectionID *uuid.UUID) ([]DriftFinding, error) {
	rows, err := q.Query(ctx, `
		select connection_id, id, name
		from resources
		where status = 'missing' and ownership = 'managed'
		  and ($1::uuid is null or connection_id = $1)
		order by connection_id, name, id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", DriftKindMissingResource, err)
	}
	defer rows.Close()

	var out []DriftFinding
	for rows.Next() {
		f := DriftFinding{
			Kind:   DriftKindMissingResource,
			Detail: "managed-ресурс исчез из целевой системы",
		}
		var resourceID uuid.UUID
		if err := rows.Scan(&f.ConnectionID, &resourceID, &f.ResourceName); err != nil {
			return nil, fmt.Errorf("inventory: drift findings %s: scan: %w", DriftKindMissingResource, err)
		}
		f.ResourceID = &resourceID
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: drift findings %s: %w", DriftKindMissingResource, err)
	}
	return out, nil
}

// AdoptBinding принимает unmanaged binding (desired_state IS NULL) под
// управление: desired становится present, status вычисляется по
// ResolveBindingStatus относительно текущего observed state (observed
// present даёт synced). Source сознательно не меняется: 'external'
// фиксирует происхождение binding, а UI отличает unmanaged по паре
// source='external' + desired IS NULL. Binding с уже заданным desired —
// ErrAlreadyManaged, несуществующий — ErrNotFound.
func (s *Store) AdoptBinding(ctx context.Context, q Querier, id uuid.UUID) (Binding, error) {
	current, err := s.GetBinding(ctx, q, id)
	if err != nil {
		return Binding{}, err
	}
	if current.DesiredState != nil {
		return Binding{}, fmt.Errorf("inventory: adopt binding %s: %w", id, ErrAlreadyManaged)
	}
	if !BindingManagementEligible(current) {
		return Binding{}, ErrBindingReadOnly
	}
	if !exclusiveObservationMatches(current) {
		return Binding{}, fmt.Errorf("inventory: adopt binding %s: %w", id, ErrBindingObservationMismatch)
	}
	desired := BindingPresent
	status := ResolveBindingStatus(&desired, current.ObservedState, current.ObservedEffective, current.Status)

	// Guard desired_state IS NULL закрывает гонку двух adopt: проигравший
	// не найдёт строку и получит ErrAlreadyManaged.
	b, err := scanBinding(q.QueryRow(ctx, `
		update bindings set desired_state = 'present', status = $2, updated_at = now()
			where id = $1 and desired_state is null and transition_operation_id is null
			  and observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb
			  and (assignment_key = '' or (
				observed_state = 'present' and observed_effective
				and observed_permission_definition_id is not null
				and observed_permission_definition_id = permission_definition_id
			  ))
			returning `+bindingColumns, id, string(status)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			latest, getErr := s.GetBinding(ctx, q, id)
			switch {
			case getErr != nil:
				return Binding{}, getErr
			case latest.DesiredState != nil:
				return Binding{}, fmt.Errorf("inventory: adopt binding %s: %w", id, ErrAlreadyManaged)
			case !BindingManagementEligible(latest):
				return Binding{}, ErrBindingReadOnly
			default:
				return Binding{}, fmt.Errorf("inventory: adopt binding %s: %w", id, ErrBindingObservationMismatch)
			}
		}
		return Binding{}, fmt.Errorf("inventory: adopt binding %s: %w", id, err)
	}
	return b, nil
}

// AdoptAccountBindings принимает доступные для управления unmanaged bindings
// учётной записи (desired_state IS NULL -> present) одним UPDATE и
// возвращает число принятых строк. Status вычисляется по правилам
// ResolveBindingStatus для desired='present' (observed present — synced,
// unknown — прежний status, absent — drift) — CASE ниже обязан оставаться
// эквивалентным этой функции. Source, как и в AdoptBinding, не меняется.
// Аккаунт без unmanaged bindings — 0 без ошибки (повторный adopt
// идемпотентен).
func (s *Store) AdoptAccountBindings(ctx context.Context, q Querier, accountID uuid.UUID) (int, error) {
	mismatch, err := s.hasExclusiveObservationMismatch(ctx, q, accountID)
	if err != nil {
		return 0, err
	}
	if mismatch {
		return 0, fmt.Errorf("inventory: adopt bindings of account %s: %w", accountID, ErrBindingObservationMismatch)
	}
	tag, err := q.Exec(ctx, `
			update bindings set
			desired_state = 'present',
			status = case
				when observed_state = 'present' then 'synced'
				when observed_state = 'unknown' then status
				else 'drift'
			end,
			updated_at = now()
			where account_id = $1 and desired_state is null
			  and observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb
			  and transition_operation_id is null
			  and not exists (
				select 1 from bindings mismatch
				where mismatch.account_id = $1
				  and mismatch.desired_state is null
				  and mismatch.observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb
				  and (
					mismatch.transition_operation_id is not null
					or (mismatch.assignment_key <> '' and not (
						mismatch.observed_state = 'present'
						and mismatch.observed_effective
						and mismatch.observed_permission_definition_id is not null
						and mismatch.observed_permission_definition_id = mismatch.permission_definition_id
					))
				  )
			  )`, accountID)
	if err != nil {
		return 0, fmt.Errorf("inventory: adopt bindings of account %s: %w", accountID, err)
	}
	if tag.RowsAffected() == 0 {
		mismatch, checkErr := s.hasExclusiveObservationMismatch(ctx, q, accountID)
		if checkErr != nil {
			return 0, checkErr
		}
		if mismatch {
			return 0, fmt.Errorf("inventory: adopt bindings of account %s: %w", accountID, ErrBindingObservationMismatch)
		}
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) hasExclusiveObservationMismatch(ctx context.Context, q Querier, accountID uuid.UUID) (bool, error) {
	var mismatch bool
	err := q.QueryRow(ctx, `
		select exists (
			select 1 from bindings b
			where b.account_id = $1
			  and b.desired_state is null
			  and b.observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb
			  and (
				b.transition_operation_id is not null
				or (b.assignment_key <> '' and not (
					b.observed_state = 'present'
					and b.observed_effective
					and b.observed_permission_definition_id is not null
					and b.observed_permission_definition_id = b.permission_definition_id
				))
			  )
		)`, accountID).Scan(&mismatch)
	if err != nil {
		return false, fmt.Errorf("inventory: inspect exclusive bindings of account %s: %w", accountID, err)
	}
	return mismatch, nil
}

// CountUnmanagedDangerousBindings считает unmanaged bindings учётной
// записи на dangerous permissions. Используется adopt-flow аккаунта для
// RBAC-гейта: массовое принятие таких bindings требует роли admin
// (симметрично точечному adoptBinding в API).
func (s *Store) CountUnmanagedDangerousBindings(ctx context.Context, q Querier, accountID uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `
		select count(*)
		from bindings b
		join permission_definitions p on p.id = b.permission_definition_id
		where b.account_id = $1 and b.desired_state is null and p.dangerous
		and b.observed_attributes->'managed_binding_eligible' is distinct from 'false'::jsonb`,
		accountID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("inventory: count unmanaged dangerous bindings of account %s: %w", accountID, err)
	}
	return n, nil
}

// DriftBaseline — находка, принятая оператором как ожидаемая: исключается
// из активного отчёта дрифта, но остаётся видимой отдельным списком.
// Находки вычисляются на лету, поэтому baseline адресует их парой
// (kind, ref_id), где ref_id — объект находки по её виду: binding для
// binding_drift/unmanaged_binding, resource для missing_resource, account
// для missing_account.
type DriftBaseline struct {
	ID           uuid.UUID
	Kind         string
	RefID        uuid.UUID
	ConnectionID uuid.UUID
	Reason       string
	CreatedBy    string
	CreatedAt    time.Time
}

// baselineKinds — виды находок, которые допустимо принимать как ожидаемые.
// connection_degraded сюда не входит (реальная авария не бывает нормой),
// credential_diverged — тоже: его чинит retry, а не признание.
var baselineKinds = map[string]bool{
	DriftKindBindingDrift:     true,
	DriftKindUnmanagedBinding: true,
	DriftKindMissingResource:  true,
	DriftKindMissingAccount:   true,
}

// BaselineableDriftKind сообщает, допускает ли вид находки baseline.
// Чистая функция для API-валидации и юнит-тестов.
func BaselineableDriftKind(kind string) bool {
	return baselineKinds[kind]
}

const driftBaselineColumns = `id, kind, ref_id, connection_id, reason, created_by, created_at`

func scanDriftBaseline(row pgx.Row) (DriftBaseline, error) {
	var b DriftBaseline
	err := row.Scan(&b.ID, &b.Kind, &b.RefID, &b.ConnectionID, &b.Reason, &b.CreatedBy, &b.CreatedAt)
	return b, err
}

// CreateDriftBaseline принимает находку как ожидаемую. Повторное принятие
// той же находки идемпотентно возвращает существующую строку: два
// оператора, увидевшие один шум, не должны получать конфликт.
func (s *Store) CreateDriftBaseline(ctx context.Context, q Querier, b DriftBaseline) (DriftBaseline, error) {
	if !BaselineableDriftKind(b.Kind) {
		return DriftBaseline{}, fmt.Errorf("inventory: drift kind %q cannot be baselined", b.Kind)
	}
	out, err := scanDriftBaseline(q.QueryRow(ctx, `
		insert into drift_baselines (kind, ref_id, connection_id, reason, created_by)
		values ($1, $2, $3, $4, $5)
		on conflict (kind, ref_id) do update set kind = excluded.kind
		returning `+driftBaselineColumns,
		b.Kind, b.RefID, b.ConnectionID, b.Reason, b.CreatedBy))
	if err != nil {
		return DriftBaseline{}, fmt.Errorf("inventory: create drift baseline: %w", err)
	}
	return out, nil
}

// DeleteDriftBaseline возвращает находку в активный дрифт.
func (s *Store) DeleteDriftBaseline(ctx context.Context, q Querier, id uuid.UUID) (DriftBaseline, error) {
	out, err := scanDriftBaseline(q.QueryRow(ctx, `
		delete from drift_baselines where id = $1 returning `+driftBaselineColumns, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DriftBaseline{}, fmt.Errorf("inventory: drift baseline %s: %w", id, ErrNotFound)
		}
		return DriftBaseline{}, fmt.Errorf("inventory: delete drift baseline: %w", err)
	}
	return out, nil
}

// ListDriftBaselines возвращает baseline-строки; connectionID == nil — по
// всем подключениям. Порядок — по времени принятия, новые первыми.
func (s *Store) ListDriftBaselines(ctx context.Context, q Querier, connectionID *uuid.UUID) ([]DriftBaseline, error) {
	query := `select ` + driftBaselineColumns + ` from drift_baselines`
	args := []any{}
	if connectionID != nil {
		query += ` where connection_id = $1`
		args = append(args, *connectionID)
	}
	query += ` order by created_at desc, id`
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: list drift baselines: %w", err)
	}
	defer rows.Close()
	out := make([]DriftBaseline, 0)
	for rows.Next() {
		b, err := scanDriftBaseline(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: list drift baselines: scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list drift baselines: %w", err)
	}
	return out, nil
}
