package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/directoryimport"
)

// Заведение принципалов из внешнего каталога (Authentik/AD).
//
// Два режима, один обработчик импорта: точечное добавление человека при
// выдаче доступа и массовая загрузка. Отличается только источник списка
// субъектов — правила заведения обязаны совпадать, иначе принципал,
// заведённый одним путём, отличался бы от заведённого другим.
//
// Роли: поиск доступен operator (он же выдаёт доступ и должен найти
// человека), импорт — тоже operator для явного списка. Массовая загрузка
// каталога требует admin: она создаёт произвольное число принципалов одним
// действием, и это решение уровня администратора, а не рядовой выдачи
// доступа.

// directoryCandidateJSON — кандидат на импорт в ответах API.
type directoryCandidateJSON struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name"`
	// Status — состояние в каталоге: active | disabled | missing.
	Status string `json:"status"`
	// Imported — принципал с такой внешней identity уже заведён.
	Imported bool `json:"imported"`
}

type directorySearchResponse struct {
	Candidates []directoryCandidateJSON `json:"candidates"`
	// Limit — фактически применённый предел выдачи. Возвращается, чтобы
	// интерфейс мог честно сказать «показаны первые N», а не делать вид,
	// что это весь каталог.
	Limit int `json:"limit"`
}

// directoryImportRequest — тело POST /api/v1/directory/import.
//
// Ровно один из режимов: subjects (явный список) либо all (перечисление
// каталога). Оба сразу — противоречие: непонятно, что делать с subjects.
type directoryImportRequest struct {
	// Subjects — явные внешние идентификаторы. Один элемент — точечное
	// добавление человека.
	Subjects []string `json:"subjects"`
	// All — загрузить перечисление каталога целиком (в пределах limit).
	All bool `json:"all"`
	// Query — необязательный отбор для режима all: позволяет загрузить не
	// весь каталог, а его часть.
	Query string `json:"query"`
	// Limit — предел перечисления в режиме all.
	Limit int `json:"limit"`
}

type directoryImportResponse struct {
	Created []principalJSON `json:"created"`
	// SkippedExisting — субъекты, у которых принципал уже был. Повторный
	// импорт штатен, поэтому это не ошибка.
	SkippedExisting []string `json:"skipped_existing"`
	// SkippedMissing — субъекты, которых каталог не знает.
	SkippedMissing []string `json:"skipped_missing"`
}

// searchDirectory — GET /api/v1/directory/users (operator).
// Пустой query перечисляет каталог, непустой ищет по подстроке.
func (s *Server) searchDirectory(w http.ResponseWriter, r *http.Request) {
	if !s.directoryEnabled(w) {
		return
	}
	limit := directoryimport.DefaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			respondError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
	}
	if limit > directoryimport.MaxLimit {
		limit = directoryimport.MaxLimit
	}

	candidates, err := s.directory.Search(r.Context(), r.URL.Query().Get("query"), limit)
	if err != nil {
		s.respondDirectoryError(w, err)
		return
	}

	out := make([]directoryCandidateJSON, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, directoryCandidateJSON{
			Subject:     c.Subject,
			DisplayName: c.DisplayName,
			Status:      string(c.Status),
			Imported:    c.Imported,
		})
	}
	respondJSON(w, http.StatusOK, directorySearchResponse{Candidates: out, Limit: limit})
}

// importDirectory — POST /api/v1/directory/import.
// Явный список субъектов доступен operator; режим all требует admin.
func (s *Server) importDirectory(w http.ResponseWriter, r *http.Request) {
	if !s.directoryEnabled(w) {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	var req directoryImportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.All && len(req.Subjects) > 0 {
		respondError(w, http.StatusBadRequest,
			"specify either subjects or all, not both: it is ambiguous what to do with subjects")
		return
	}
	if !req.All && len(req.Subjects) == 0 {
		respondError(w, http.StatusBadRequest, "subjects are required unless all is set")
		return
	}
	// Массовая загрузка создаёт произвольное число принципалов одним
	// действием — это решение уровня администратора.
	if req.All && !sess.Role.Allows(auth.RoleAdmin) {
		respondError(w, http.StatusForbidden, "importing the whole directory requires admin role")
		return
	}

	var (
		result directoryimport.Result
		err    error
	)
	if req.All {
		result, err = s.directory.ImportAll(r.Context(), req.Query, req.Limit)
	} else {
		result, err = s.directory.ImportSubjects(r.Context(), req.Subjects)
	}
	if err != nil {
		s.respondDirectoryError(w, err)
		return
	}

	created := make([]principalJSON, 0, len(result.Created))
	for i := range result.Created {
		created = append(created, toPrincipalJSON(result.Created[i]))
	}
	s.writeDirectoryImportAudit(r.Context(), sess, result)

	respondJSON(w, http.StatusOK, directoryImportResponse{
		Created:         created,
		SkippedExisting: emptyIfNil(result.SkippedExisting),
		SkippedMissing:  emptyIfNil(result.SkippedMissing),
	})
}

// directoryEnabled отвечает 501, когда каталог не подключён или не умеет
// перечислять. Это состояние конфигурации, а не ошибка запроса: сообщаем
// прямо, чтобы интерфейс мог скрыть соответствующие действия.
func (s *Server) directoryEnabled(w http.ResponseWriter) bool {
	if s.directory == nil || !s.directory.Enabled() {
		respondError(w, http.StatusNotImplemented,
			"identity directory import is not configured for this installation")
		return false
	}
	return true
}

// respondDirectoryError переводит ошибки импорта в коды ответа.
// Недоступность каталога — 502: это отказ внешней зависимости, а не вина
// вызывающего, и повтор запроса имеет смысл.
func (s *Server) respondDirectoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, directoryimport.ErrNotConfigured),
		errors.Is(err, directoryimport.ErrSearchUnsupported):
		respondError(w, http.StatusNotImplemented,
			"identity directory import is not configured for this installation")
	default:
		respondError(w, http.StatusBadGateway, "identity directory is unavailable: "+err.Error())
	}
}

// writeDirectoryImportAudit фиксирует заведение принципалов одним событием
// на импорт: интерес представляет само действие оператора, а у созданных
// принципалов есть собственные события principal.created.
//
// Пишется после создания, отдельной транзакцией: принципалы уже заведены, и
// откатывать их из-за сбоя журналирования неправильно. Ошибка записи
// логируется и не превращает успешный импорт в отказ.
func (s *Server) writeDirectoryImportAudit(ctx context.Context, sess auth.Session, result directoryimport.Result) {
	if len(result.Created) == 0 {
		return
	}
	subjects := make([]string, 0, len(result.Created))
	for i := range result.Created {
		subjects = append(subjects, result.Created[i].ExternalSubject)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "api: audit directory import", "error", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionPrincipalImported,
		Result:    audit.ResultSuccess,
	}, map[string]any{
		"created":          len(result.Created),
		"skipped_existing": len(result.SkippedExisting),
		"skipped_missing":  len(result.SkippedMissing),
		"subjects":         subjects,
	}); err != nil {
		slog.ErrorContext(ctx, "api: audit directory import", "error", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.ErrorContext(ctx, "api: audit directory import", "error", err)
	}
}

// auditActionPrincipalImported — заведение принципалов из каталога.
// Отличимо от principal.created ручного создания: по action видно, что
// источником была не форма оператора, а каталог.
const auditActionPrincipalImported = "principal.imported_from_directory"
