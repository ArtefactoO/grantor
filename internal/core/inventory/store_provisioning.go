package inventory

// Провижининг managed-аккаунтов: создание строки-резервации до того, как
// учётная запись подтверждена в целевой системе.
//
// Почему отдельный статус, а не «создавать строку только после успеха»:
// операция account.create ссылается на account_id и обязана существовать в
// той же транзакции, что и постановка job (idempotency key, lifecycle
// reservation, parent bulk). Строка нужна и как резервация identity —
// уникальность (connection_id, engine_identity) не даёт двум параллельным
// запросам развести два аккаунта на одно имя. Поэтому строка создаётся
// сразу, но в статусе provisioning: живым managed-аккаунтом она станет
// только после подтверждённого Apply+Verify адаптера.
//
// Почему провалившийся create НЕ откатывает строку: операция ретраится
// (River) и может быть повторена оператором. Удаление строки на первой
// ошибке сделало бы retry невозможным, а повторный запрос доступа —
// источником дублей. Оставленная запись provisioning идемпотентна:
// следующая попытка находит её по identity, переиспользует и ставит новый
// account.create.

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// CreateProvisioningAccount создаёт managed login-аккаунт в статусе
// provisioning: identity зарезервирована, но учётной записи в целевой
// системе ещё нет. Ошибки те же, что у CreateManagedAccount
// (ErrAlreadyExists при занятой identity, ErrNotFound по FK).
//
// Реализован композицией поверх CreateManagedAccount, чтобы отображение
// ошибок PostgreSQL и список колонок оставались в одном месте: обе
// операции идут в транзакции вызывающего, поэтому промежуточный active
// снаружи не наблюдаем.
func (s *Store) CreateProvisioningAccount(ctx context.Context, q Querier, params CreateManagedAccountParams) (Account, error) {
	a, err := s.CreateManagedAccount(ctx, q, params)
	if err != nil {
		return Account{}, err
	}
	if err := s.SetAccountStatus(ctx, q, a.ID, AccountProvisioning); err != nil {
		return Account{}, err
	}
	a.Status = AccountProvisioning
	return a, nil
}

// markMissingAccounts переводит в missing аккаунты connection, которых не
// оказалось в снапшоте discovery, — и managed, и unmanaged. Симметрично
// markMissingResources: discovery ничего не удаляет.
//
// Затрагиваются только живые статусы (active, disabled): provisioning
// принадлежит незавершённой операции create и меняется её lifecycle-
// гвардами, deleted — tombstone, повторный missing по уже missing строке
// не пишет ничего (updated_at не бампается).
//
// Вызывающий обязан убедиться, что снапшот вообще содержит инвентарь
// аккаунтов (capability inventory.accounts включена у connection): иначе
// пустой список аккаунтов означал бы «adapter их не собирает», а не «их
// нет на target». Возвращает количество помеченных строк.
func (s *Store) markMissingAccounts(ctx context.Context, q Querier, connectionID uuid.UUID, ids map[string]uuid.UUID, observed []string) (int, error) {
	present := make([]uuid.UUID, 0, len(observed))
	for _, identity := range observed {
		if id, ok := ids[identity]; ok {
			present = append(present, id)
		}
	}
	// Ownership не фильтруется сознательно: unmanaged-строка удалённого из
	// кластера пользователя иначе висела бы active вечно. Provisioning и
	// deleted не трогаются — они собственность незавершённой операции и
	// tombstone-механики.
	tag, err := q.Exec(ctx, `
		update accounts set status = 'missing', updated_at = now()
		where connection_id = $1
		  and status in ('active', 'disabled')
		  and not (id = any($2))`,
		connectionID, present,
	)
	if err != nil {
		return 0, fmt.Errorf("inventory: mark missing accounts: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
