package adapter

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Нормализация прав: единое представление для всех движков.
//
// Имена permission definitions приходят от адаптеров в их внутренней нотации
// (`vhost-access:project`, `topic-produce:orders`, `SELECT ON ads.*`,
// `acl:topic:literal:orders:read:allow`). Раньше эти строки разбирал
// frontend, повторяя логику каждого адаптера; при изменении нотации в
// адаптере UI молча начинал показывать неверную подпись. Разбор перенесён
// сюда: адаптер — единственное место, которое знает свою нотацию.
//
// Нормализация опирается на Attributes, а не на разбор Name: адаптеры уже
// кладут в атрибуты структурированные поля (kind, resource_type, operation,
// vhost, rules), и читать их надёжнее, чем реконструировать по строке.
// Разбор имени остаётся запасным путём для исторических записей, у которых
// атрибутов нет.
//
// Что здесь НЕ определяется: direct/inherited, managed/unmanaged и
// present/missing. Это факты binding, а не определения права — одно и то же
// определение у разных аккаунтов имеет разный статус. Они добавляются на
// API-слое, где binding доступен.

// PermissionCategory — чем право является в терминах движка. Значение —
// стабильный английский идентификатор; человекочитаемые подписи собирает UI,
// поэтому русский текст сюда не попадает.
type PermissionCategory string

const (
	// PermissionRole — именованная роль (postgres, mysql, clickhouse, mongodb).
	PermissionRole PermissionCategory = "role"
	// PermissionPrivilege — прямая привилегия на объект (clickhouse GRANT).
	PermissionPrivilege PermissionCategory = "privilege"
	// PermissionACL — отдельная ACL-запись (kafka, redis).
	PermissionACL PermissionCategory = "acl"
	// PermissionBundle — назначаемый набор правил (redis read/write/admin).
	PermissionBundle PermissionCategory = "bundle"
	// PermissionTag — серверный тег пользователя (rabbitmq).
	PermissionTag PermissionCategory = "tag"
	// PermissionVhost — доступ к vhost (rabbitmq).
	PermissionVhost PermissionCategory = "vhost"
	// PermissionTopic — доступ к топику (kafka bundles).
	PermissionTopic PermissionCategory = "topic"
	// PermissionUnknown — нотация не распознана. Право не скрывается: UI
	// показывает его через Raw. Это осознанный запасной путь, а не ошибка.
	PermissionUnknown PermissionCategory = "unknown"
)

// PermissionDetail — одна специфичная для движка характеристика права.
// Key — стабильный английский идентификатор (`resource_type`, `pattern`,
// `key_patterns`), подпись к нему подбирает UI. Порядок в срезе значим:
// адаптер задаёт его от общего к частному, UI выводит как есть.
type PermissionDetail struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PermissionView — движко-независимое представление одного права.
//
// Пустая строка в Action, Resource или Scope означает «к этому праву
// неприменимо» (у роли postgres нет ресурса, у кластерного права kafka нет
// scope). UI такие поля не показывает, а не рисует пустую строку.
type PermissionView struct {
	// Category — чем право является в движке.
	Category PermissionCategory `json:"category"`
	// Action — нормализованное действие в словаре движка: read, write,
	// admin, SELECT, configure. Пусто, если право не про действие (роль).
	Action string `json:"action"`
	// Resource — объект, на который выдано право: топик, база, таблица,
	// vhost, шаблон ключей.
	Resource string `json:"resource"`
	// Scope — область действия: база, схема, vhost, pattern, host.
	Scope string `json:"scope"`
	// Dangerous дублирует флаг определения права, чтобы представление было
	// самодостаточным.
	Dangerous bool `json:"dangerous"`
	// DangerReason — почему право опасно, в терминах движка. Заполняется
	// только при Dangerous: причина без опасности бессмысленна.
	DangerReason string `json:"danger_reason"`
	// Details — специфичные для движка характеристики.
	Details []PermissionDetail `json:"details"`
	// Raw — полное исходное выражение права, без сокращений. Заполнено
	// всегда: это то, что пользователь должен иметь возможность прочитать и
	// скопировать целиком, каким бы ни был движок.
	Raw string `json:"raw"`
}

// PermissionRef — вход нормализации: несекретные поля определения права
// ровно в том виде, в каком они лежат в permission_definitions, плюс
// разрешённое имя scope-ресурса (в таблице хранится только его id).
type PermissionRef struct {
	ExternalID string
	Name       string
	ScopeName  string
	Assignable bool
	Dangerous  bool
	Attributes map[string]any
}

// PermissionNormalizer — дополнительный контракт adapter для движков,
// желающих объяснить свою нотацию прав. Метод обязан быть чистой функцией
// от переданных метаданных: сети и target он не касается, поэтому работает
// одинаково в direct- и connector-режиме и вызывается на API-слое при
// сериализации ответа.
//
// Adapter, не реализующий контракт, получает generic-представление: право
// остаётся видимым, но без разобранных полей.
type PermissionNormalizer interface {
	NormalizePermission(ref PermissionRef) PermissionView
}

// NormalizePermission приводит определение права к единому представлению.
// Неизвестный движок (adapter не зарегистрирован в этом процессе) и adapter
// без PermissionNormalizer — не ошибка вызывающего: возвращается
// generic-представление, право не исчезает из выдачи.
func NormalizePermission(engine string, ref PermissionRef) PermissionView {
	a, err := New(engine)
	if err != nil {
		return GenericPermissionView(ref)
	}
	n, ok := a.(PermissionNormalizer)
	if !ok {
		return GenericPermissionView(ref)
	}
	view := n.NormalizePermission(ref)
	// Raw обязателен по контракту: подстраховываемся, чтобы ошибка одного
	// адаптера не оставила пользователя без исходного значения.
	if view.Raw == "" {
		view.Raw = RawPermissionExpression(ref)
	}
	return view
}

// GenericPermissionView — представление для движков без нормализатора и
// запасной путь внутри адаптеров, когда имя не совпало ни с одним известным
// паттерном. Ресурсом считается само имя: показать имя целиком лучше, чем
// не показать ничего.
func GenericPermissionView(ref PermissionRef) PermissionView {
	return PermissionView{
		Category:     PermissionUnknown,
		Resource:     ref.Name,
		Scope:        ref.ScopeName,
		Dangerous:    ref.Dangerous,
		DangerReason: genericDangerReason(ref),
		Details:      AttributeDetails(ref.Attributes),
		Raw:          RawPermissionExpression(ref),
	}
}

// genericDangerReason — честная формулировка для случая, когда движок
// пометил право опасным, но объяснить причину структурно мы не можем.
func genericDangerReason(ref PermissionRef) string {
	if !ref.Dangerous {
		return ""
	}
	return "the engine marks this permission as dangerous"
}

// RawPermissionExpression собирает полное исходное выражение права.
// Scope дописывается только когда он есть и не дублируется в имени: у
// адаптеров распространён паттерн `<verb>:<scope>`, и повтор лишь удлиняет
// строку.
func RawPermissionExpression(ref PermissionRef) string {
	// Достаточно проверки на подстроку: имена вида `vhost-access:project`
	// со scope `project` именно так и устроены.
	if ref.ScopeName == "" || strings.Contains(ref.Name, ref.ScopeName) {
		return ref.Name
	}
	return ref.Name + " @ " + ref.ScopeName
}

// AttributeDetails превращает произвольные атрибуты в детали со стабильным
// порядком (по ключу). Служебный ключ kind пропускается: он уже выражен
// категорией. Порядок фиксирован, иначе панель подробностей переставляла бы
// строки между запросами.
func AttributeDetails(attrs map[string]any) []PermissionDetail {
	if len(attrs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		if k == "kind" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]PermissionDetail, 0, len(keys))
	for _, k := range keys {
		v := FormatAttributeValue(attrs[k])
		if v == "" {
			continue
		}
		out = append(out, PermissionDetail{Key: k, Value: v})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// FormatAttributeValue приводит значение атрибута к строке для показа.
// Пустая строка означает «показывать нечего» (nil, пустой список): такие
// детали отбрасываются, чтобы не засорять панель.
func FormatAttributeValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		// JSON-числа приходят float64; целые показываем без дробной части.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case []string:
		return joinNonEmpty(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if s := FormatAttributeValue(item); s != "" {
				parts = append(parts, s)
			}
		}
		return joinNonEmpty(parts)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// joinNonEmpty склеивает непустые значения через запятую.
func joinNonEmpty(items []string) string {
	kept := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			kept = append(kept, item)
		}
	}
	return strings.Join(kept, ", ")
}

// AttrString читает строковый атрибут. Отсутствие и неверный тип
// неразличимы намеренно: и то и другое означает «этого поля нет».
func AttrString(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	s, ok := attrs[key].(string)
	if !ok {
		return ""
	}
	return s
}

// AttrStrings читает атрибут-список строк. Значение переживает сериализацию
// в JSON и обратно, поэтому принимается и []string, и []any: из БД атрибуты
// приходят вторым вариантом, из свежего discovery — первым.
func AttrStrings(attrs map[string]any, key string) []string {
	if attrs == nil {
		return nil
	}
	switch v := attrs[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// AttrBool читает булев атрибут; отсутствие означает false.
func AttrBool(attrs map[string]any, key string) bool {
	if attrs == nil {
		return false
	}
	b, ok := attrs[key].(bool)
	if !ok {
		return false
	}
	return b
}
