package jobs

// Классификация отказов операции на детерминированные (терминальные) и
// повторяемые.
//
// Мотивация: MaxAttempts River одинаков для всех jobs, поэтому отказ, исход
// которого не зависит от повтора, раньше держал операцию в ретраях минутами, а
// более поздняя попытка перезаписывала исходную причину другим — уже
// вводящим в заблуждение — текстом (например, первая попытка сообщала
// «движок не поддерживает изменение», а четвёртая, после посторонней
// успешной операции над тем же аккаунтом, — «lifecycle conflict»).
//
// Терминальными считаются только те отказы, где повтор той же операции над тем
// же состоянием даёт ровно тот же результат:
//   - движок/подключение не поддерживает изменение (adapter.ErrUnsupportedChange,
//     adapter.ErrCredentialProofUnsupported) — capability не появляется от
//     повтора;
//   - целевая identity существует, но не принадлежит нам
//     (adapter.ErrExternalIdentityConflict) — повтор не вправе её присвоить;
//   - job относится к прежнему поколению lifecycle аккаунта или к другому его
//     статусу (inventory.ErrAccountLifecycleConflict,
//     inventory.ErrAccountStatusConflict) — состояние уехало, и повтор ИМЕННО
//     этой операции бессмыслен: нужна новая операция поверх нового состояния;
//   - payload операции не разбирается или kind неизвестен — payload
//     неизменяем, повтор разберёт тот же байт-в-байт payload.
//
// Всё остальное (сеть, недоступный Vault/target/metadata database, отказ
// записи audit) остаётся повторяемым: временная недоступность dependency не
// должна превращаться в окончательный отказ (README, «Безопасность операций»).

import (
	"errors"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// terminalErrorPrefix — durable-маркер терминальной причины в колонке
// operations.error. Между попытками job переживает только строка операции,
// поэтому признак «причина детерминирована» хранится в самом тексте ошибки, а
// не в отдельной колонке или памяти worker. Исходный текст сохраняется
// целиком сразу за маркером.
const terminalErrorPrefix = "not retryable: "

// terminalError помечает ошибку как детерминированный отказ там, где по
// sentinel это неочевидно: например, восстановленный (sanitized) текст
// account.restore уже не несёт исходную цепочку ошибок, а kind/payload
// операции вообще не имеют своего sentinel.
type terminalError struct{ cause error }

// Error возвращает текст исходной ошибки без изменений: пометка меняет
// политику повторов, а не сообщение оператору.
func (e *terminalError) Error() string { return e.cause.Error() }

// Unwrap сохраняет причину для errors.Is/As вызывающих.
func (e *terminalError) Unwrap() error { return e.cause }

// terminal помечает err как детерминированный отказ. nil остаётся nil.
func terminal(err error) error {
	if err == nil {
		return nil
	}
	return &terminalError{cause: err}
}

// isTerminal сообщает, что повтор операции с этой ошибкой заведомо не изменит
// исход. Классификация идёт по sentinel-ошибкам (errors.Is проходит и через
// обёртки executor, и через errors.Join), поэтому не зависит от текста.
func isTerminal(err error) bool {
	if err == nil {
		return false
	}
	var marked *terminalError
	if errors.As(err, &marked) {
		return true
	}
	switch {
	case errors.Is(err, adapter.ErrUnsupportedChange),
		errors.Is(err, adapter.ErrCredentialProofAccessDenied),
		errors.Is(err, adapter.ErrCredentialProofUnsupported),
		errors.Is(err, adapter.ErrTargetIdentityConflict),
		errors.Is(err, adapter.ErrExternalIdentityConflict),
		errors.Is(err, inventory.ErrAccountLifecycleConflict),
		errors.Is(err, inventory.ErrAccountStatusConflict):
		return true
	default:
		return false
	}
}

// markTerminalErrorText добавляет к тексту ошибки операции durable-маркер
// терминальной причины. Идемпотентно: уже помеченный текст не удваивается.
func markTerminalErrorText(text string) string {
	if text == "" || hasTerminalErrorText(text) {
		return text
	}
	return terminalErrorPrefix + text
}

// hasTerminalErrorText сообщает, что записанный в операцию текст ошибки уже
// содержит терминальную причину предыдущей попытки. Worker использует это,
// чтобы повторная доставка job не перезапустила операцию и не затёрла
// исходную причину более поздним (и, как правило, менее точным) текстом.
func hasTerminalErrorText(text string) bool {
	return strings.HasPrefix(text, terminalErrorPrefix)
}
