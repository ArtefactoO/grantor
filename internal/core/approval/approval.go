// Package approval — политика confirmation gate опасных операций
// (ADR-0010; docs/threat-model.md P1, R3). Опасная изменяющая операция не
// выполняется, пока admin явно её не подтвердит: она входит в pending_approval
// и не диспатчится воркеру до approve. Это **не** four-eyes: подтвердить
// операцию может тот же admin, что и запросил (self-approval — штатный и
// основной случай); правило «approver != requester» не применяется. Второй
// admin допустим, но не обязателен.
//
// Пакет не хранит состояние и не ходит в БД: он держит только чистые решения
// (какие операции требуют подтверждения; является ли approve self-approval —
// для явной отметки в audit) и нормализацию причины. Жизненный цикл операции
// (статус pending_approval, переходы approve/reject) живёт в
// internal/core/operations; запись audit — в internal/core/audit.
package approval

import "strings"

// MaxReasonLen — предел длины причины approve/reject. Причина — короткий
// комментарий admin для журнала, а не документ; ограничение защищает audit
// metadata и колонку operations.decision_reason от разрастания.
const MaxReasonLen = 1024

// Requires сообщает, требует ли изменяющая операция подтверждения вторым
// admin перед выполнением.
//
// Критерий намеренно узкий и явный: подтверждение требуется только когда
// gate включён (enabled, флаг GRANTOR_APPROVAL_REQUIRED) И операция выдаёт
// опасную привилегию (dangerous — классификация адаптера, permission.Dangerous).
// Опасность определяет адаптер (postgres CREATEROLE/superuser, mongo dbOwner/
// root и т.п.), поэтому политика не дублирует эту логику, а переиспользует
// готовый флаг. Одиночный отзыв доступа — безопасное направление и под gate не
// попадает (согласовано с dangerousGrantCheck: revoke не требует confirm);
// массовый отзыв гейтится отдельным порогом (RequiresMassRevoke).
//
// Чистая функция — тестируется без БД и окружения.
func Requires(enabled, dangerous bool) bool {
	return enabled && dangerous
}

// RequiresMassRevoke сообщает, требуют ли revoke-операции одного применения
// (одного bulk/manifest parent) подтверждения admin перед выполнением из-за
// своего масштаба: revokes — число отзывов в этом применении, threshold —
// порог GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD.
//
// Порог защищает от массового offboarding по ошибке (fat-finger манифест,
// стирающий сотни bindings): если одно применение отзывает БОЛЬШЕ threshold
// bindings, ВСЕ revoke-children этого parent создаются в pending_approval и
// ждут явного approve. threshold <= 0 отключает gate (дефолт — безопасно
// обратно совместим, как GRANTOR_APPROVAL_REQUIRED=false); revokes <=
// threshold — «безопасное направление» в малом объёме, отзыв ставится сразу.
//
// Порог намеренно НЕ зависит от флага GRANTOR_APPROVAL_REQUIRED: тот гейтит
// опасные привилегии (направление «выдать больше прав»), а этот — масштаб
// отзыва. Оба механизма используют один и тот же lifecycle
// (CreateParams.RequiresApproval -> pending_approval -> approve/reject), но
// включаются независимо: достаточно выставить threshold > 0.
//
// Чистая функция — тестируется без БД и окружения.
func RequiresMassRevoke(threshold, revokes int) bool {
	return threshold > 0 && revokes > threshold
}

// IsSelf сообщает, что подтверждающий совпадает с запросившим операцию
// (self-approval). Актор идентифицируется парой (тип, id) — ровно так же, как
// пишется в operations.actor_type/actor_id и audit (auth.Session.ActorType/
// ActorID): человек — ("user", email), service-принципал — ("service", id).
//
// Self-approval РАЗРЕШЁН и является штатным случаем: результат используется не
// для блокировки, а как явная отметка self_approved в audit-событии
// operation.approved (чтобы журнал недвусмысленно показывал, что один и тот же
// admin и запросил, и подтвердил операцию).
//
// Чистая функция — тестируется без БД.
func IsSelf(requesterType, requesterID, approverType, approverID string) bool {
	return requesterType == approverType && requesterID == approverID
}

// NormalizeReason приводит причину approve/reject к каноничному виду: срезает
// пробелы по краям и обрезает до MaxReasonLen рун (не байт), чтобы многобайтовый
// UTF-8 не рвался посередине. Пустая причина допустима: комментарий
// необязателен, ключевой контроль — сам факт второго подтверждения.
func NormalizeReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if r := []rune(reason); len(r) > MaxReasonLen {
		return string(r[:MaxReasonLen])
	}
	return reason
}
