// Package accessmanifest — декларативный манифест управляемых доступов
// (ADR-0009). Манифест описывает желаемый набор managed-грантов в терминах
// имён (principal / connection / role), а не внутренних id: его можно
// хранить в git, сравнивать (plan/dry-run), применять (apply) и выгружать
// из текущего состояния (export).
//
// # Модель
//
// Одна запись Entry — это «у принципала P в подключении C должна
// присутствовать (или отсутствовать) роль R». Принципал резолвится по
// external_subject или display_name, подключение — по display_name или id,
// роль — по permission external_id или name внутри подключения.
//
// # Границы
//
//   - Манифест описывает ТОЛЬКО перечисленные доступы. По умолчанию (prune
//     выключен) записи, которых в манифесте нет, не трогаются: план не
//     отзывает managed-доступы, отсутствующие в манифесте. Полная
//     реконсиляция включается флагом Prune (см. plan.go).
//   - Unmanaged bindings (source='external', desired_state IS NULL) не
//     трогаются никогда: ни plan, ни apply, ни prune их не отзывают.
//   - Scope у Entry нет: одна запись — это право целиком, в его собственной
//     области действия. Для cluster-wide прав это binding с
//     scope_resource_id IS NULL, для прав, неотделимых от ресурса (topic
//     kafka, база mongodb, vhost rabbitmq) — binding на этом ресурсе; вывод
//     области един для манифеста и API (inventory.EffectiveBindingScope).
//     Bindings, суженные оператором до чужого ресурса, вне модели манифеста,
//     и prune их не затрагивает.
package accessmanifest

import (
	"errors"
	"fmt"
	"strings"
)

// Version — единственная поддерживаемая версия схемы манифеста.
const Version = "v1"

// maxEntries — предел числа записей одного манифеста: защита от случайной
// постановки неограниченного объёма работы одним запросом.
const maxEntries = 1000

// State — желаемое состояние доступа записи манифеста.
type State string

const (
	// StatePresent — доступ должен присутствовать (значение по умолчанию
	// для записи с пустым state).
	StatePresent State = "present"
	// StateAbsent — доступ должен отсутствовать.
	StateAbsent State = "absent"
)

// Entry — одна запись манифеста: роль принципала в подключении с желаемым
// состоянием. Principal — external_subject или display_name принципала;
// Connection — display_name или id подключения; Role — permission
// external_id или name внутри подключения. Пустой State трактуется как
// present.
//
// yaml-теги зеркалируют json-теги: манифест принимается и в JSON, и в YAML,
// оба формата декодируются в одну структуру (единственный источник
// валидации). Паритет тегов закреплён рефлексивным тестом.
type Entry struct {
	Principal  string `json:"principal" yaml:"principal"`
	Connection string `json:"connection" yaml:"connection"`
	Role       string `json:"role" yaml:"role"`
	State      string `json:"state,omitempty" yaml:"state,omitempty"`
}

// Manifest — декларативный набор желаемых managed-доступов. Prune включает
// полную реконсиляцию (см. plan.go); Environment — необязательный фильтр/
// ассерт окружения (записи, чьи подключения в другом окружении, попадают в
// Unresolved на plan и пропускаются на export). yaml-теги — зеркало
// json-тегов (см. Entry).
type Manifest struct {
	Version     string  `json:"version" yaml:"version"`
	Environment string  `json:"environment,omitempty" yaml:"environment,omitempty"`
	Prune       bool    `json:"prune,omitempty" yaml:"prune,omitempty"`
	Entries     []Entry `json:"entries" yaml:"entries"`
}

// stateOrDefault возвращает желаемое состояние записи; пустой state
// трактуется как present.
func (e Entry) stateOrDefault() State {
	if e.State == "" {
		return StatePresent
	}
	return State(e.State)
}

// Validate проверяет манифест целиком: поддерживаемую версию, предел числа
// записей и корректность каждой записи. Возвращает первую ошибку.
func (m Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("manifest version %q is not supported, want %q", m.Version, Version)
	}
	if len(m.Entries) > maxEntries {
		return fmt.Errorf("manifest has %d entries, at most %d allowed", len(m.Entries), maxEntries)
	}
	for i := range m.Entries {
		if err := m.Entries[i].validate(); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
	}
	return nil
}

// validate проверяет обязательные поля записи и допустимость state.
func (e Entry) validate() error {
	if strings.TrimSpace(e.Principal) == "" {
		return errors.New("principal is required")
	}
	if strings.TrimSpace(e.Connection) == "" {
		return errors.New("connection is required")
	}
	if strings.TrimSpace(e.Role) == "" {
		return errors.New("role is required")
	}
	switch State(e.State) {
	case "", StatePresent, StateAbsent:
		return nil
	default:
		return fmt.Errorf("invalid state %q, want %q or %q", e.State, StatePresent, StateAbsent)
	}
}
