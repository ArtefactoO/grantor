package api

// Синхронная проверка capability движка до постановки операции.
//
// Мотивация: операция, отклонённая adapter'ом как неподдерживаемая
// (adapter.ErrUnsupportedChange), — детерминированный отказ. Worker снимает
// такую операцию с ретраев сразу (internal/jobs/terminal.go), но пользователю
// честнее получить синхронный 409 в ответе на запрос, чем 202 и failed-операцию
// в списке. Тот же приём уже применяется для account.restore
// (handlers_accounts.go).

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
)

var errConnectionCapabilityUnavailable = errors.New("connection capability is unavailable")

// requireConnectionCapability preserves the unknown-engine contract while
// rejecting capabilities explicitly removed by this connection's discovery.
func requireConnectionCapability(conn connections.Connection, capability adapter.Capability) error {
	if conn.AuthMode == "none" {
		return fmt.Errorf("authentication_disabled: %s is unavailable for connection %s: %w", capability, conn.ID, errConnectionCapabilityUnavailable)
	}
	if _, err := adapter.New(conn.Engine); err != nil {
		return nil
	}
	if !engineSupports(conn.Engine, capability) ||
		!slices.Contains(connectionCapabilitiesForProjection(conn), string(capability)) {
		return fmt.Errorf("%s is unavailable for connection %s: %w", capability, conn.ID,
			errConnectionCapabilityUnavailable)
	}
	return nil
}

// engineSupports сообщает, объявляет ли движок capability в своём manifest.
//
// Незарегистрированный в этом процессе движок считается поддерживающим:
// контракт неизвестен, и API не вправе отказывать по незнанию — решение
// остаётся за worker, где adapter точно зарегистрирован. Тот же принцип
// «неизвестный движок — не ошибка вызывающего» использует
// adapter.FormatEngineIdentity.
func engineSupports(engine string, capability adapter.Capability) bool {
	ad, err := adapter.New(engine)
	if err != nil {
		return true
	}
	return ad.Manifest().HasCapability(capability)
}

// engineProvesCredential сообщает, умеет ли движок ПОДТВЕРДИТЬ переданный
// пароль на целевой системе (реализует adapter.CredentialProver). Это не
// capability манифеста, а контракт Go-интерфейса: тот же признак допускает
// account.restore (internal/jobs) и он же — единственное условие adopt
// mode=verify_password.
//
// В отличие от engineSupports незарегистрированный движок здесь считается
// НЕумеющим: разрешать «по незнанию» операцию, весь смысл которой в
// доказательстве, нельзя — worker всё равно откажет, но уже после того, как
// проверяемый пароль окажется в Vault.
func engineProvesCredential(engine string) bool {
	ad, err := adapter.New(engine)
	if err != nil {
		return false
	}
	_, ok := ad.(adapter.CredentialProver)
	return ok
}
