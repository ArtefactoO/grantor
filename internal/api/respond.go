package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// maxRequestBody — предел размера JSON-тела запроса.
const maxRequestBody = 1 << 20 // 1 MiB

// errorResponse — единый формат JSON-ошибок API: {"error": msg}.
type errorResponse struct {
	Error string `json:"error"`
}

// respondJSON пишет JSON-ответ с заданным статусом. Ошибка записи не
// возвращается: ответ уже начат, повлиять на него нельзя.
func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("api: write response", "error", err)
	}
}

// respondError пишет JSON-ошибку {"error": msg} с заданным статусом.
func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, errorResponse{Error: msg})
}

// respondStoreError переводит известные ошибки stores в HTTP-статусы:
// not found -> 404, конфликт статуса, недопустимый переход и занятый
// уникальный ключ -> 409, остальное -> 500 с generic-сообщением (детали
// только в лог: тексты внутренних ошибок наружу не отдаются).
func respondStoreError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrStatsMembershipUnsupported), errors.Is(err, adapter.ErrPostgresObjectACL):
		respondError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errConnectionCapabilityUnavailable):
		respondError(w, http.StatusConflict, err.Error())
	case errors.Is(err, connections.ErrNotFound),
		errors.Is(err, operations.ErrNotFound),
		errors.Is(err, inventory.ErrNotFound),
		errors.Is(err, principals.ErrNotFound):
		respondError(w, http.StatusNotFound, "not found")
	case errors.Is(err, inventory.ErrAlreadyExists),
		errors.Is(err, principals.ErrAlreadyExists):
		respondError(w, http.StatusConflict, "already exists")
	case errors.Is(err, inventory.ErrAlreadyManaged):
		respondError(w, http.StatusConflict, "binding is already managed")
	case errors.Is(err, inventory.ErrBindingAlreadyPresent):
		respondError(w, http.StatusConflict, "access is already assigned")
	case errors.Is(err, connections.ErrStatusConflict),
		errors.Is(err, operations.ErrStatusConflict),
		errors.Is(err, inventory.ErrAccountStatusConflict),
		errors.Is(err, inventory.ErrAccountLifecycleConflict),
		errors.Is(err, inventory.ErrAccountLifecycleBusy),
		errors.Is(err, inventory.ErrAssignmentOccupied),
		errors.Is(err, inventory.ErrBindingObservationMismatch),
		errors.Is(err, inventory.ErrBindingReadOnly),
		errors.Is(err, inventory.ErrBindingTransitionConflict):
		respondError(w, http.StatusConflict, "status conflict; retry after reloading current state")
	case isAdminCredentialChangeSQLConflict(err):
		respondError(w, http.StatusConflict, "connection admin credential change is active; retry after it finishes")
	case errors.Is(err, connections.ErrVersionConflict):
		respondError(w, http.StatusConflict, "connection was changed; retry after reloading current state")
	case errors.Is(err, connections.ErrInvalidTransition),
		errors.Is(err, operations.ErrInvalidTransition):
		respondError(w, http.StatusConflict, "status transition is not allowed")
	case errors.Is(err, errWeakAuthNotConfirmed):
		// Текст сообщения здесь информативен и секретов не содержит: он
		// называет учётку и говорит, чего не хватает (confirm=true).
		respondError(w, http.StatusBadRequest, err.Error())
	default:
		slog.ErrorContext(ctx, "api: internal error", "error", err)
		respondError(w, http.StatusInternalServerError, "internal error")
	}
}

func isAdminCredentialChangeSQLConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55006" &&
		pgErr.ConstraintName == "connection_admin_credential_changes_active_idx"
}

// rejectUnknownQuery отклоняет запрос с query-параметром вне списка
// разрешённых: 400 с именем лишнего параметра. Возвращает false, если ответ
// уже записан.
//
// Молчаливое игнорирование опечатки опаснее отказа там, где параметр СУЖАЕТ
// выборку: `connection_id=` вместо `connection=` выгружало манифест всего
// парка вместо одного подключения, а с `prune` такой манифест означает
// массовый отзыв доступов по опечатке в одну букву.
func rejectUnknownQuery(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	known := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		known[name] = true
	}
	for name := range r.URL.Query() {
		if !known[name] {
			respondError(w, http.StatusBadRequest, fmt.Sprintf(
				"unknown query parameter %q; supported: %s", name, strings.Join(allowed, ", ")))
			return false
		}
	}
	return true
}

// decodeJSON читает JSON-тело запроса (лимит maxRequestBody); при ошибке
// пишет 400 и возвращает false.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// decodeOptionalJSON читает НЕОБЯЗАТЕЛЬНОЕ JSON-тело запроса (лимит
// maxRequestBody): пустое тело оставляет dst нулевым и считается успехом.
// Нужно ручкам, у которых тело появилось позже самой ручки (rotate аккаунта
// с флагом detach, rotate принципала с confirm): прежние клиенты и UI шлют
// POST без тела, и требовать его — сломать совместимость. Некорректный JSON
// по-прежнему 400: молча игнорировать заданный, но нечитаемый флаг нельзя —
// запрос выполнился бы не с тем намерением.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	if err := json.Unmarshal(body, dst); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// pathUUID разбирает path-параметр {name} как UUID; при ошибке пишет 400
// и возвращает false.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}

// queryInt возвращает целочисленный query-параметр или def, если
// параметр отсутствует. Нечисловое значение — ошибка.
func queryInt(r *http.Request, name string, def int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: expected integer", name)
	}
	return n, nil
}

// maxPageLimit — верхний предел параметра ?limit пагинации. Значение выше
// не ошибка: оно кэпится, чтобы один запрос не вычитывал неограниченный
// объём (см. queryLimit).
const maxPageLimit = 500

// queryLimit возвращает limit из query-параметра name, ограниченный
// сверху maxPageLimit. Отсутствие параметра даёт def (обычно 0 — стор
// применяет собственный дефолт). Значение выше максимума кэпится до него,
// а не отвергается: клиент получает не больше, чем предусмотрено. Значения
// <= 0 пробрасываются как есть (стор трактует их как дефолт). Нечисловое
// значение — ошибка (наследуется от queryInt).
func queryLimit(r *http.Request, name string, def int) (int, error) {
	n, err := queryInt(r, name, def)
	if err != nil {
		return 0, err
	}
	if n > maxPageLimit {
		return maxPageLimit, nil
	}
	return n, nil
}

// queryUUID возвращает UUID query-параметр или nil, если параметр
// отсутствует. Невалидный UUID — ошибка.
func queryUUID(r *http.Request, name string) (*uuid.UUID, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: expected UUID", name)
	}
	return &id, nil
}

// session извлекает auth.Session из контекста запроса. При её отсутствии
// пишет 401 unauthorized и возвращает ok=false. RequireRole уже гарантирует
// сессию на всех endpoints, поэтому ветка ok=false — защита от неверного
// wiring; helper собирает воедино повторявшуюся идиому
// FromContext+respondError(401).
func (s *Server) session(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	sess, ok := auth.FromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return auth.Session{}, false
	}
	return sess, true
}

// writeAudit сериализует metadata в ev.Metadata (ошибку оборачивает как
// "api: marshal audit metadata: %w") и пишет событие через audit.Writer в
// переданном Querier (пул или транзакция). Собирает воедино идиому
// marshal-then-write мутирующих handlers; вызывающий обрабатывает
// возвращённую ошибку через respondStoreError, как и раньше.
func (s *Server) writeAudit(ctx context.Context, q audit.Querier, ev audit.Event, metadata any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("api: marshal audit metadata: %w", err)
	}
	ev.Metadata = raw
	return s.audit.Write(ctx, q, ev)
}

// bulkParent описывает parent-операцию bulk-оркестрации: kind, опциональный
// principal, parent payload (маршалится внутри runBulkParent), audit action
// и wrap-префиксы ошибок маршалинга payload и commit. extraResponse — доп.
// верхнеуровневые поля ответа 202 (manifest apply добавляет actions_count).
type bulkParent struct {
	kind             string
	connectionID     *uuid.UUID
	accountID        *uuid.UUID
	principalID      *uuid.UUID
	payload          any
	payloadErrPrefix string
	auditAction      string
	commitErrPrefix  string
	extraResponse    map[string]any
	// afterCommit — необязательный hook, выполняемый после успешного
	// Commit и до записи ответа. Используется offboard принципала для
	// best-effort зачистки его общих секретов из Vault: побочный эффект вне
	// транзакции не должен случиться до фиксации метаданных, а его отказ не
	// откатывает уже закоммиченную оркестрацию (только warning в лог).
	afterCommit func()
}

// runBulkParent проводит общую для четырёх bulk-эндпоинтов оркестрацию
// (bulk grant, principal-centric access/rotate, manifest apply):
// Begin → marshal parent payload → operations.Create(parent) →
// Transition(pending→running) → buildChildren → audit → Commit →
// respondJSON(202, {operation_id, children, ...extraResponse}).
//
// buildChildren получает транзакцию и id parent, строит свои дочерние
// операции и возвращает slice детей (для JSON-ответа) вместе с метаданными
// audit. При ошибке buildChildren сам пишет ответ (respondStoreError/
// respondError/scope) и возвращает ok=false — тогда runBulkParent просто
// выходит, а отложенный Rollback откатывает транзакцию (тот же порядок и
// границы транзакции, что были в каждом эндпоинте до выделения helper).
func (s *Server) runBulkParent(w http.ResponseWriter, r *http.Request, sess auth.Session, p bulkParent,
	buildChildren func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool)) {
	ctx := r.Context()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	parentPayload, err := json.Marshal(p.payload)
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("%s: %w", p.payloadErrPrefix, err))
		return
	}
	parent, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          p.kind,
		ConnectionID:  p.connectionID,
		AccountID:     p.accountID,
		PrincipalID:   p.principalID,
		Payload:       parentPayload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Parent не выполняется worker: переводится в running сразу и живёт в
	// нём, пока выполняются дети. Итоговый статус (success/partial/failed)
	// проставляет финализация в базе при завершении последнего ребёнка
	// (operations.Store.FinalizeParent); дети создаются ниже в этой же
	// транзакции, поэтому окна «parent running без детей» снаружи не видно.
	if _, err := s.operations.Transition(ctx, tx, parent.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	children, metadata, ok := buildChildren(tx, parent.ID)
	if !ok {
		return
	}

	// Bulk без детей завершается здесь же: вся работа выполнилась
	// метаданными этой транзакции, и некому финализировать parent позже.
	if _, _, err := s.operations.FinalizeParent(ctx, tx, parent.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       p.auditAction,
		ConnectionID: p.connectionID,
		AccountID:    p.accountID,
		PrincipalID:  p.principalID,
		OperationID:  &parent.ID,
		Result:       audit.ResultSuccess,
	}, metadata); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("%s: %w", p.commitErrPrefix, err))
		return
	}
	if p.afterCommit != nil {
		p.afterCommit()
	}
	resp := map[string]any{
		"operation_id": parent.ID,
		"children":     children,
	}
	for k, v := range p.extraResponse {
		resp[k] = v
	}
	respondJSON(w, http.StatusAccepted, resp)
}
