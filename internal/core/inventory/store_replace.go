package inventory

// Транзакционные переходы exclusive assignment. В отличие от обычного grant
// replacement не создаёт вторую binding-строку: один физический слот остаётся
// одной строкой, а desired permission атомарно меняется A -> B. Observed-поля
// при reserve не трогаются и продолжают описывать реально действующий A до
// подтверждённого Apply/Verify.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrBindingTransitionConflict означает, что binding уже изменился либо
// принадлежит другой transition-операции. Повтор со stale payload не вправе
// обращаться к target.
var ErrBindingTransitionConflict = errors.New("inventory: binding transition conflict")

// AccessReplacementTransition пинит одну фазу replacement. ExpectedVersion —
// версия ПОСЛЕ reserve; до reserve строка обязана иметь ExpectedVersion-1.
type AccessReplacementTransition struct {
	BindingID          uuid.UUID
	OperationID        uuid.UUID
	FromPermissionID   uuid.UUID
	ToPermissionID     uuid.UUID
	AssignmentKey      string
	ExpectedVersion    int64
	ExpectedAttributes json.RawMessage
}

func (p AccessReplacementTransition) validate() error {
	if p.BindingID == uuid.Nil || p.OperationID == uuid.Nil ||
		p.FromPermissionID == uuid.Nil || p.ToPermissionID == uuid.Nil {
		return errors.New("binding, operation, from permission and to permission are required")
	}
	if p.FromPermissionID == p.ToPermissionID {
		return errors.New("from permission and to permission must differ")
	}
	if p.AssignmentKey == "" {
		return errors.New("assignment key is required")
	}
	if p.ExpectedVersion <= 0 {
		return errors.New("expected version must be positive")
	}
	return nil
}

// ReserveAccessReplacement атомарно резервирует смену permission на той же
// binding-строке. Guard одновременно проверяет текущую версию/owner перехода,
// принадлежность target permission тому же connection, scope и assignment
// slot. Никакого target side effect этот метод не выполняет.
func (s *Store) ReserveAccessReplacement(ctx context.Context, q Querier, p AccessReplacementTransition) (Binding, error) {
	if err := p.validate(); err != nil {
		return Binding{}, fmt.Errorf("inventory: reserve access replacement: %w", err)
	}
	// Сериализуемся со старым grant/revoke этой же строки. FOR UPDATE важен:
	// worker мог уже исполнять target side effect, хотя его running ещё не
	// виден вне транзакции. После ожидания READ COMMITTED перечитает статус.
	rows, err := q.Query(ctx, `
		select id from operations
		where binding_id = $1 and id <> $2
		  and status in ('pending_approval', 'pending', 'running')
		for update`, p.BindingID, p.OperationID)
	if err != nil {
		return Binding{}, fmt.Errorf("inventory: reserve access replacement %s: inspect active operations: %w",
			p.BindingID, err)
	}
	busy := rows.Next()
	rows.Close()
	if err := rows.Err(); err != nil {
		return Binding{}, fmt.Errorf("inventory: reserve access replacement %s: inspect active operations: %w",
			p.BindingID, err)
	}
	if busy {
		return Binding{}, fmt.Errorf("inventory: reserve access replacement %s: active binding operation: %w",
			p.BindingID, ErrBindingTransitionConflict)
	}
	b, err := scanBinding(q.QueryRow(ctx, `
		update bindings as b set
			permission_definition_id = $4,
			desired_state = 'present',
			source = 'service',
			status = 'pending',
			transition_operation_id = $2,
			binding_version = $6,
			updated_at = now()
		where b.id = $1
		  and b.permission_definition_id = $3
		  and b.assignment_key = $5
		  and b.desired_state = 'present'
		  and b.transition_operation_id is null
		  and b.binding_version = $6 - 1
		  and exists (
			select 1
			from permission_definitions next
			join accounts a on a.id = b.account_id
			where next.id = $4
			  and next.connection_id = a.connection_id
			  and next.assignment_key = b.assignment_key
			  and next.scope_resource_id is not distinct from b.scope_resource_id
			  and next.assignable
			  and next.status = 'observed'
		  )
		returning `+bindingColumnsB,
		p.BindingID, p.OperationID, p.FromPermissionID, p.ToPermissionID,
		p.AssignmentKey, p.ExpectedVersion,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// После начала Apply rollback запрещён, но оператор может явно
			// запросить reverse B -> A. Takeover допустим только у failed
			// access.replace и только строго обратно по его pinned payload.
			reversed, reverseErr := scanBinding(q.QueryRow(ctx, `
				update bindings as b set
					permission_definition_id = $4,
					desired_state = 'present',
					status = 'pending',
					transition_operation_id = $2,
					binding_version = $6,
					updated_at = now()
				from operations old
				where b.id = $1
				  and b.permission_definition_id = $3
				  and b.assignment_key = $5
				  and b.desired_state = 'present'
				  and b.transition_operation_id = old.id
				  and b.binding_version = $6 - 1
				  and old.kind = 'access.replace'
				  and old.status = 'failed'
				  and old.payload->>'from_permission_definition_id' = $4::uuid::text
				  and old.payload->>'to_permission_definition_id' = $3::uuid::text
				  and exists (
					select 1 from permission_definitions next
					join accounts a on a.id = b.account_id
					where next.id = $4
					  and next.connection_id = a.connection_id
					  and next.assignment_key = b.assignment_key
					  and next.scope_resource_id is not distinct from b.scope_resource_id
					  and next.assignable and next.status = 'observed'
				  )
				returning `+bindingColumnsB,
				p.BindingID, p.OperationID, p.FromPermissionID, p.ToPermissionID,
				p.AssignmentKey, p.ExpectedVersion,
			))
			if reverseErr == nil {
				return reversed, nil
			}
			if !errors.Is(reverseErr, pgx.ErrNoRows) {
				return Binding{}, fmt.Errorf("inventory: reverse failed access replacement %s: %w",
					p.BindingID, reverseErr)
			}
			return Binding{}, fmt.Errorf("inventory: reserve access replacement %s: %w",
				p.BindingID, ErrBindingTransitionConflict)
		}
		return Binding{}, fmt.Errorf("inventory: reserve access replacement %s: %w", p.BindingID, err)
	}
	return b, nil
}

// RejectAccessReplacement откатывает только ещё принадлежащий operation
// переход. Permission возвращается к A, transition owner снимается, а версия
// увеличивается, чтобы уже выданный worker payload стал stale. Target до
// approval не трогался, поэтому observed A сохраняется.
func (s *Store) RejectAccessReplacement(ctx context.Context, q Querier, p AccessReplacementTransition) (Binding, error) {
	if err := p.validate(); err != nil {
		return Binding{}, fmt.Errorf("inventory: reject access replacement: %w", err)
	}
	b, err := scanBinding(q.QueryRow(ctx, `
		update bindings as b set
			permission_definition_id = $3,
			transition_operation_id = null,
			binding_version = binding_version + 1,
			status = case
				when b.observed_state = 'unknown' then 'pending'
				when b.observed_state = 'present'
				 and b.observed_effective
				 and b.observed_permission_definition_id = $3 then 'synced'
				else 'drift'
			end,
			updated_at = now()
		where b.id = $1
		  and b.transition_operation_id = $2
		  and b.permission_definition_id = $4
		  and b.assignment_key = $5
		  and b.binding_version = $6
		returning `+bindingColumnsB,
		p.BindingID, p.OperationID, p.FromPermissionID, p.ToPermissionID,
		p.AssignmentKey, p.ExpectedVersion,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, fmt.Errorf("inventory: reject access replacement %s: %w",
				p.BindingID, ErrBindingTransitionConflict)
		}
		return Binding{}, fmt.Errorf("inventory: reject access replacement %s: %w", p.BindingID, err)
	}
	return b, nil
}

// CompleteAccessReplacement фиксирует exact Apply/Verify B. Guard не даёт
// старому job завершить более новый переход; expected attributes берутся из
// зафиксированного permission template, а не из payload операции.
func (s *Store) CompleteAccessReplacement(ctx context.Context, q Querier, p AccessReplacementTransition) (Binding, error) {
	if err := p.validate(); err != nil {
		return Binding{}, fmt.Errorf("inventory: complete access replacement: %w", err)
	}
	var pinned any
	if len(p.ExpectedAttributes) > 0 {
		pinned = []byte(p.ExpectedAttributes)
	}
	b, err := scanBinding(q.QueryRow(ctx, `
		update bindings as b set
			observed_state = 'present',
			observed_effective = true,
			observed_permission_definition_id = $3,
			observed_attributes = coalesce($6::jsonb, next.attributes),
			status = 'synced',
			transition_operation_id = null,
			binding_version = binding_version + 1,
			updated_at = now()
		from permission_definitions next
		where b.id = $1
		  and b.transition_operation_id = $2
		  and b.permission_definition_id = $3
		  and b.assignment_key = $4
		  and b.binding_version = $5
		  and next.id = $3
		  and next.assignment_key = b.assignment_key
		  and ($6::jsonb is null or next.attributes = $6::jsonb)
		returning `+bindingColumnsB,
		p.BindingID, p.OperationID, p.ToPermissionID, p.AssignmentKey, p.ExpectedVersion, pinned,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, fmt.Errorf("inventory: complete access replacement %s: %w",
				p.BindingID, ErrBindingTransitionConflict)
		}
		return Binding{}, fmt.Errorf("inventory: complete access replacement %s: %w", p.BindingID, err)
	}
	return b, nil
}

// MarkAccessReplacementFailed помечает только текущий переход. Transition
// owner сохраняется: retry той же операции может снова выполнить exact PUT B;
// другой operation с устаревшей версией не пройдёт guard.
func (s *Store) MarkAccessReplacementFailed(ctx context.Context, q Querier, p AccessReplacementTransition) error {
	if err := p.validate(); err != nil {
		return fmt.Errorf("inventory: mark access replacement failed: %w", err)
	}
	tag, err := q.Exec(ctx, `
		update bindings set status = 'failed', updated_at = now()
		where id = $1
		  and transition_operation_id = $2
		  and permission_definition_id = $3
		  and assignment_key = $4
		  and binding_version = $5`,
		p.BindingID, p.OperationID, p.ToPermissionID, p.AssignmentKey, p.ExpectedVersion,
	)
	if err != nil {
		return fmt.Errorf("inventory: mark access replacement %s failed: %w", p.BindingID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("inventory: mark access replacement %s failed: %w",
			p.BindingID, ErrBindingTransitionConflict)
	}
	return nil
}
