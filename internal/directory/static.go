package directory

import (
	"context"
	"errors"
	"strings"
)

// Static — mock-провайдер identity directory для dev-контура и стендов без
// каталога (GRANTOR_IDP_MODE=static): статусы субъектов задаются статически
// двумя списками, сеть не используется. Позволяет прогнать полный
// offboarding-путь (poll → principal.disabled → security.offboarding_incomplete)
// без AD/Authentik; в production не предназначен — боевой каталог
// подключается провайдером ldap (ванильная AD и Authentik LDAP outpost
// работают существующим NewLDAP без нового кода).
//
// Семантика: субъект из disabled — StatusDisabled; из missing — StatusMissing
// (учётка «удалена из каталога»); все остальные — StatusActive. Ошибок у
// провайдера не бывает (каталога нет), поэтому ложные прерывания прогона
// исключены.
type Static struct {
	disabled map[string]struct{}
	missing  map[string]struct{}
	// roster — субъекты, которые провайдер соглашается перечислять
	// (Searcher). Пустой roster означает, что перечисление недоступно:
	// статические списки disabled/missing описывают отклонения, а не
	// каталог целиком, и выдавать их за полный список людей нельзя.
	roster []string
}

var (
	_ Provider = (*Static)(nil)
	_ Searcher = (*Static)(nil)
)

// NewStatic строит mock-провайдер из списков субъектов. Значения обрезаются
// по пробелам, пустые игнорируются; missing имеет приоритет над disabled,
// если субъект указан в обоих (более сильный сигнал offboarding).
func NewStatic(disabled, missing []string) *Static {
	s := &Static{
		disabled: make(map[string]struct{}, len(disabled)),
		missing:  make(map[string]struct{}, len(missing)),
	}
	for _, subj := range disabled {
		if subj = strings.TrimSpace(subj); subj != "" {
			s.disabled[subj] = struct{}{}
		}
	}
	for _, subj := range missing {
		if subj = strings.TrimSpace(subj); subj != "" {
			s.missing[subj] = struct{}{}
		}
	}
	return s
}

// Statuses возвращает статус каждого запрошенного субъекта по статическим
// спискам. Контракт Provider соблюдён: запись есть для каждого субъекта,
// ошибок не бывает.
func (s *Static) Statuses(_ context.Context, subjects []string) (map[string]Status, error) {
	out := make(map[string]Status, len(subjects))
	for _, subj := range subjects {
		out[subj] = s.status(subj)
	}
	return out, nil
}

// status определяет статус одного субъекта. Выделено, чтобы Statuses и
// Search отвечали про один и тот же субъект одинаково.
func (s *Static) status(subj string) Status {
	switch {
	case has(s.missing, subj):
		return StatusMissing
	case has(s.disabled, subj):
		return StatusDisabled
	default:
		return StatusActive
	}
}

// has сообщает о наличии субъекта в наборе.
func has(set map[string]struct{}, subj string) bool {
	_, ok := set[subj]
	return ok
}

// WithRoster задаёт список субъектов, доступных для перечисления и импорта
// (GRANTOR_IDP_STATIC_SUBJECTS). Позволяет прогнать полный путь заведения
// принципалов из каталога на стенде без AD/Authentik. Возвращает тот же
// Static (chained wiring, как WithAudit у Runner).
func (s *Static) WithRoster(subjects []string) *Static {
	for _, subj := range subjects {
		if subj = strings.TrimSpace(subj); subj != "" {
			s.roster = append(s.roster, subj)
		}
	}
	return s
}

// Search перечисляет субъекты roster (контракт — см. Searcher). Статус
// каждого берётся из тех же списков, что и у Statuses, поэтому выключенный
// в «каталоге» субъект и здесь виден выключенным.
func (s *Static) Search(_ context.Context, query string, limit int) ([]Entry, error) {
	if limit <= 0 {
		return nil, errors.New("directory: static: search limit must be positive")
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := make([]Entry, 0, len(s.roster))
	for _, subj := range s.roster {
		if len(out) >= limit {
			break
		}
		if q != "" && !strings.Contains(strings.ToLower(subj), q) {
			continue
		}
		out = append(out, Entry{
			Subject:     subj,
			DisplayName: subj,
			Status:      s.status(subj),
		})
	}
	return out, nil
}
