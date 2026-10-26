package api

// Список движков, доступных для создания подключения. Источник истины —
// registry адаптеров процесса (cmd/api регистрирует те же адаптеры, что
// worker/connector): фронт больше не дублирует перечень и не расходится с
// бэкендом при добавлении нового движка.

import (
	"net/http"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// enginesResponse — тело GET /api/v1/engines.
type enginesResponse struct {
	// Engines — отсортированные ключи зарегистрированных адаптеров
	// (postgres, kafka, …). Отображаемые имена и иконки — забота UI.
	Engines []string `json:"engines"`
}

// listEngines — GET /api/v1/engines (viewer): ключи движков из registry.
func (s *Server) listEngines(w http.ResponseWriter, r *http.Request) {
	if !rejectUnknownQuery(w, r) {
		return
	}
	respondJSON(w, http.StatusOK, enginesResponse{Engines: adapter.Engines()})
}
