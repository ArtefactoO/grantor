package api

import "net/http"

// runtimeConfigJSON — безопасная allowlist runtime-настроек, смысл которых
// оператор должен видеть в UI. Не сериализуем Server/config целиком: там могут
// появиться адреса и секретные параметры.
type runtimeConfigJSON struct {
	ScopeEnforcement string `json:"scope_enforcement"`
}

// getRuntimeConfig — GET /api/v1/runtime-config (admin). Режим берётся из
// уже распарсенного startup config и потому отражает фактическое поведение
// текущего API process, а не наличие строк scope_policies.
func (s *Server) getRuntimeConfig(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, runtimeConfigJSON{
		ScopeEnforcement: string(s.scopeEnforcement),
	})
}
