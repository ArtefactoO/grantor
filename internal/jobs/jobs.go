// Package jobs — диспетчер durable jobs для операций grantor
// (docs/architecture.md, раздел 19). Бизнес-слой зависит только от
// интерфейсов Executor и Dispatcher; конкретная реализация на River
// живёт в этом же пакете (river.go) и наружу не протекает.
package jobs

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// Executor выполняет бизнес-логику одной операции: строит plan, вызывает
// adapter, записывает result. Реализация появится на этапе 1; в тестах
// используется фейк. Execute обязан быть идемпотентным: повторный вызов
// для той же операции не должен ломать целевое состояние.
type Executor interface {
	Execute(ctx context.Context, op operations.Operation) error
}

// Dispatcher транзакционно ставит операцию в очередь выполнения.
// EnqueueOperationTx вызывается в той же транзакции, где создаётся
// строка operations: либо коммитятся и операция, и job, либо ничего —
// это даёт durable постановку без окна потери.
type Dispatcher interface {
	EnqueueOperationTx(ctx context.Context, tx pgx.Tx, operationID uuid.UUID) error
	// EnqueueOperationSequenceTx ставит операции строго последовательно:
	// следующая появляется в очереди только после успешного завершения
	// предыдущей. Все строки operations должны быть созданы заранее в tx.
	EnqueueOperationSequenceTx(ctx context.Context, tx pgx.Tx, operationIDs ...uuid.UUID) error
}

// OperationArgs — аргументы job выполнения операции. Job несёт только
// id: всё состояние операции живёт в таблице operations, что делает
// повторное выполнение job безопасным.
type OperationArgs struct {
	OperationID      uuid.UUID   `json:"operation_id"`
	NextOperationIDs []uuid.UUID `json:"next_operation_ids,omitempty"`
}

// Kind возвращает тип job для River.
func (OperationArgs) Kind() string {
	return "operation.execute"
}
