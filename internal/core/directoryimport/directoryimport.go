// Package directoryimport заводит принципалов из внешнего identity
// directory (Authentik, AD, любой другой каталог за contract
// internal/directory).
//
// Зачем отдельный пакет. internal/directory отвечает на вопросы о каталоге,
// internal/core/principals владеет принципалами, а связывание одного с
// другим — самостоятельное решение со своими правилами: кого заводить, что
// делать с уже существующими, чем ограничивать массовую загрузку. Класть
// это в любой из двух пакетов значило бы дать ему знание о втором.
//
// # Два режима одним примитивом
//
// Оба сценария сводятся к одному действию — «завести принципалов по списку
// субъектов»:
//
//   - точечный: оператор ищет человека при выдаче доступа и заводит одного.
//     Это режим по умолчанию, потому что он не создаёт в системе строк,
//     которыми никто не пользуется;
//   - массовый: администратор загружает каталог целиком или его часть.
//     Список субъектов при этом приходит не от человека, а из перечисления
//     каталога, ограниченного лимитом.
//
// Разделять их на две реализации незачем: отличается только источник
// списка, а правила заведения обязаны совпадать — иначе принципал,
// заведённый точечно, отличался бы от заведённого массово.
//
// # Правила заведения
//
//   - идемпотентность по внешней identity: повторный импорт того же
//     субъекта не создаёт второго принципала и не считается ошибкой.
//     Каталог опрашивают периодически, и импорт обязан переживать повтор;
//   - субъект, отсутствующий в каталоге (StatusMissing), не заводится:
//     завести принципала, который сразу подлежит offboarding-детекции,
//     значит создать заведомый мусор;
//   - выключенный в каталоге (StatusDisabled) заводится, но сразу
//     disabled — он существует, и скрывать его от оператора неправильно,
//     однако выдавать ему доступ без осознанного включения нельзя.
package directoryimport

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/directory"
)

// ErrSearchUnsupported возвращается, когда каталог настроен, но его
// провайдер не умеет перечислять субъектов. Это не ошибка вызывающего:
// провайдер может отвечать только про известные субъекты.
var ErrSearchUnsupported = errors.New("directoryimport: directory does not support search")

// ErrNotConfigured возвращается, когда каталог не подключён вовсе.
var ErrNotConfigured = errors.New("directoryimport: directory is not configured")

// MaxLimit — верхний предел одного перечисления каталога. Существует, чтобы
// «загрузить всех» не превращалось в неограниченную операцию: каталог
// организации может содержать десятки тысяч записей, а импорт создаёт по
// строке на каждую.
const MaxLimit = 1000

// DefaultLimit — предел, применяемый когда вызывающий его не задал.
const DefaultLimit = 50

// Candidate — запись каталога вместе с тем, что о ней известно grantor.
type Candidate struct {
	Subject     string
	DisplayName string
	Status      directory.Status
	// Imported — принципал с такой внешней identity уже существует.
	// Позволяет интерфейсу показать, кого добавлять не нужно, не заставляя
	// оператора выяснять это самостоятельно.
	Imported bool
}

// Result — итог импорта. Разделение created/skipped существенно: повторный
// импорт того же списка — штатная ситуация, и «0 создано, 5 пропущено»
// должно читаться как успех, а не как отказ.
type Result struct {
	Created []principals.Principal
	// SkippedExisting — субъекты, у которых принципал уже был.
	SkippedExisting []string
	// SkippedMissing — субъекты, которых каталог не знает.
	SkippedMissing []string
}

// Service заводит принципалов из каталога.
type Service struct {
	pool       *pgxpool.Pool
	principals *principals.Store
	provider   directory.Provider
	// providerName — значение principals.external_provider для заведённых
	// принципалов. Оно же связывает их с поллингом статусов
	// (GRANTOR_IDP_PROVIDER), поэтому обязано совпадать.
	providerName string
}

// New собирает сервис. nil-провайдер оставляет импорт выключенным: методы
// вернут ErrNotConfigured.
func New(pool *pgxpool.Pool, provider directory.Provider, providerName string) *Service {
	return &Service{
		pool:         pool,
		principals:   principals.NewStore(),
		provider:     provider,
		providerName: strings.TrimSpace(providerName),
	}
}

// ProviderName возвращает имя каталога (external_provider заведённых
// принципалов); пусто, если каталог не сконфигурирован.
func (s *Service) ProviderName() string {
	if s == nil || s.provider == nil {
		return ""
	}
	return s.providerName
}

// ExternalIdentityObservation переводит статус каталога в зеркальный статус
// принципала: missing означает deleted — субъекта в каталоге больше нет.
func ExternalIdentityObservation(st directory.Status) (principals.ExternalIdentityStatus, error) {
	switch st {
	case directory.StatusActive:
		return principals.ExternalIdentityActive, nil
	case directory.StatusDisabled:
		return principals.ExternalIdentityDisabled, nil
	case directory.StatusMissing:
		return principals.ExternalIdentityDeleted, nil
	default:
		return "", fmt.Errorf("unsupported directory status %q", st)
	}
}

// Enabled сообщает, доступен ли импорт: нужен и каталог, и умение
// перечислять.
func (s *Service) Enabled() bool {
	if s == nil || s.provider == nil {
		return false
	}
	_, ok := s.provider.(directory.Searcher)
	return ok
}

// Search возвращает кандидатов на импорт. Пустой query перечисляет каталог
// (в пределах limit) — это режим массовой загрузки; непустой отбирает по
// подстроке — режим поиска человека при выдаче доступа.
func (s *Service) Search(ctx context.Context, query string, limit int) ([]Candidate, error) {
	if s == nil || s.provider == nil {
		return nil, ErrNotConfigured
	}
	searcher, ok := s.provider.(directory.Searcher)
	if !ok {
		return nil, ErrSearchUnsupported
	}

	entries, err := searcher.Search(ctx, query, clampLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("directoryimport: search: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}

	subjects := make([]string, 0, len(entries))
	for _, e := range entries {
		subjects = append(subjects, e.Subject)
	}
	known, err := s.existingSubjects(ctx, subjects)
	if err != nil {
		return nil, err
	}

	out := make([]Candidate, 0, len(entries))
	for _, e := range entries {
		out = append(out, Candidate{
			Subject:     e.Subject,
			DisplayName: e.DisplayName,
			Status:      e.Status,
			Imported:    known[e.Subject],
		})
	}
	return out, nil
}

// ImportSubjects заводит принципалов по явному списку субъектов — тот же
// путь, что и точечное добавление одного человека.
//
// Статусы субъектов сверяются с каталогом до создания: список приходит от
// вызывающего и может содержать что угодно, а заводить принципала, которого
// каталог не знает, нельзя.
func (s *Service) ImportSubjects(ctx context.Context, subjects []string) (Result, error) {
	if s == nil || s.provider == nil {
		return Result{}, ErrNotConfigured
	}
	wanted := dedupe(subjects)
	if len(wanted) == 0 {
		return Result{}, errors.New("directoryimport: no subjects to import")
	}
	if len(wanted) > MaxLimit {
		return Result{}, fmt.Errorf("directoryimport: %d subjects exceed the limit of %d", len(wanted), MaxLimit)
	}

	statuses, err := s.provider.Statuses(ctx, wanted)
	if err != nil {
		return Result{}, fmt.Errorf("directoryimport: statuses: %w", err)
	}

	names, err := s.displayNames(ctx, wanted)
	if err != nil {
		return Result{}, err
	}

	var result Result
	for _, subject := range wanted {
		if statuses[subject] == directory.StatusMissing {
			result.SkippedMissing = append(result.SkippedMissing, subject)
			continue
		}
		name := names[subject]
		if name == "" {
			name = subject
		}
		p, err := s.principals.Create(ctx, s.pool, principals.CreateParams{
			Type:             principals.TypeHuman,
			DisplayName:      name,
			ExternalProvider: s.providerName,
			ExternalSubject:  subject,
		})
		if err != nil {
			// Уже заведён — штатный исход повторного импорта, а не сбой.
			if errors.Is(err, principals.ErrAlreadyExists) {
				result.SkippedExisting = append(result.SkippedExisting, subject)
				continue
			}
			return result, fmt.Errorf("directoryimport: create principal for %q: %w", subject, err)
		}
		// Выключенный в каталоге заводится сразу выключенным: он существует
		// и скрывать его неправильно, но выдавать доступ человеку, которого
		// каталог уже заблокировал, нельзя без осознанного включения.
		// Создание и перевод статуса — два шага: Create не принимает статус,
		// а расширять его ради импорта значило бы усложнить общий путь.
		if statuses[subject] == directory.StatusDisabled {
			disabled, err := s.principals.SetStatus(ctx, s.pool, p.ID, principals.StatusDisabled)
			if err != nil {
				return result, fmt.Errorf("directoryimport: disable imported principal %q: %w", subject, err)
			}
			p = disabled
		}
		// Статус каталога уже получен — зеркало пишется сразу, иначе до
		// первого поллинга принципал висит «Not checked». Локальный переход
		// не нужен: disabled обработан выше.
		mirror, err := ExternalIdentityObservation(statuses[subject])
		if err != nil {
			return result, fmt.Errorf("directoryimport: mirror status for %q: %w", subject, err)
		}
		update, err := s.principals.RecordExternalIdentityStatus(ctx, s.pool, p.ID, mirror, false)
		if err != nil {
			return result, fmt.Errorf("directoryimport: record mirror status for %q: %w", subject, err)
		}
		result.Created = append(result.Created, update.Principal)
	}
	return result, nil
}

// ImportAll заводит принципалов по перечислению каталога — режим массовой
// загрузки. Возвращает столько же, сколько завёл бы вызов ImportSubjects со
// списком из Search: одни и те же правила заведения.
func (s *Service) ImportAll(ctx context.Context, query string, limit int) (Result, error) {
	candidates, err := s.Search(ctx, query, limit)
	if err != nil {
		return Result{}, err
	}
	subjects := make([]string, 0, len(candidates))
	for _, c := range candidates {
		// Отсутствующих в каталоге перечисление не возвращает, но
		// проверка дешёвая и делает намерение явным.
		if c.Status == directory.StatusMissing {
			continue
		}
		subjects = append(subjects, c.Subject)
	}
	if len(subjects) == 0 {
		return Result{}, nil
	}
	return s.ImportSubjects(ctx, subjects)
}

// displayNames добирает отображаемые имена из каталога. Провайдер без
// перечисления имён не даёт — тогда именем становится сам субъект.
func (s *Service) displayNames(ctx context.Context, subjects []string) (map[string]string, error) {
	searcher, ok := s.provider.(directory.Searcher)
	if !ok {
		return nil, nil
	}
	out := map[string]string{}
	for _, subject := range subjects {
		entries, err := searcher.Search(ctx, subject, 1)
		if err != nil {
			return nil, fmt.Errorf("directoryimport: lookup %q: %w", subject, err)
		}
		for _, e := range entries {
			if e.Subject == subject {
				out[subject] = e.DisplayName
			}
		}
	}
	return out, nil
}

// existingSubjects возвращает субъекты, для которых принципал уже заведён.
func (s *Service) existingSubjects(ctx context.Context, subjects []string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		select external_subject from principals
		where external_provider = $1 and external_subject = any($2)`,
		s.providerName, subjects)
	if err != nil {
		return nil, fmt.Errorf("directoryimport: load existing principals: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			return nil, fmt.Errorf("directoryimport: scan existing principal: %w", err)
		}
		out[subject] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("directoryimport: load existing principals: %w", err)
	}
	return out, nil
}

// clampLimit приводит лимит к допустимому диапазону.
func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultLimit
	case limit > MaxLimit:
		return MaxLimit
	default:
		return limit
	}
}

// dedupe убирает пустые и повторяющиеся субъекты, сохраняя порядок.
func dedupe(subjects []string) []string {
	seen := make(map[string]bool, len(subjects))
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
