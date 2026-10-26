package redis

import (
	"sort"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав Redis. Правила ACL — плоская строка токенов
// (`~* &* +@read -@dangerous`), в которой смешаны разные по смыслу вещи:
// шаблоны ключей, каналы Pub/Sub, категории команд и отдельные команды.
// Показывать её одной строкой означает заставлять человека парсить глазами,
// поэтому токены раскладываются по видам.
//
// Классификация — по префиксу токена, как их задаёт сам Redis:
//
//	~pattern, %R~pattern, %W~pattern — шаблоны ключей;
//	&pattern                        — каналы Pub/Sub;
//	+@category, -@category          — категории команд;
//	+command, -command              — отдельные команды;
//	(...)                           — вложенный селектор.
//
// Нераспознанный токен не выбрасывается, а попадает в отдельную деталь:
// потерять правило в выдаче хуже, чем показать его неразобранным.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// NormalizePermission объясняет нотацию прав Redis.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	rules := adapter.AttrString(ref.Attributes, "rules")
	switch adapter.AttrString(ref.Attributes, "kind") {
	case "bundle":
		return adapter.PermissionView{
			Category: adapter.PermissionBundle,
			// Имя bundle (read/write/monitoring/admin) — и есть действие.
			Action:       ref.Name,
			Dangerous:    ref.Dangerous,
			DangerReason: aclDangerReason(ref.Dangerous),
			Details:      append(ruleDetails(rules), bundleCaveats(ref.Name)...),
			Raw:          adapter.RawPermissionExpression(ref),
		}
	case "acl":
		return adapter.PermissionView{
			Category:     adapter.PermissionACL,
			Resource:     rules,
			Dangerous:    ref.Dangerous,
			DangerReason: aclDangerReason(ref.Dangerous),
			Details:      ruleDetails(rules),
			Raw:          adapter.RawPermissionExpression(ref),
		}
	default:
		return adapter.GenericPermissionView(ref)
	}
}

// aclDangerReason объясняет опасность правил: флаг ставится, когда правила
// целиком разрешают хотя бы одну команду из dangerousProbeCommands.
func aclDangerReason(dangerous bool) string {
	if !dangerous {
		return ""
	}
	return "the rules fully allow at least one dangerous command"
}

// ruleDetails раскладывает строку правил по видам токенов. Внутри каждого
// вида порядок сохраняется как в правилах: он значим — Redis применяет
// правила последовательно, и `+@all -@admin` не то же самое, что наоборот.
func ruleDetails(rules string) []adapter.PermissionDetail {
	if strings.TrimSpace(rules) == "" {
		return nil
	}
	buckets := map[string][]string{}
	order := make([]string, 0, 5)
	add := func(key, token string) {
		if _, seen := buckets[key]; !seen {
			order = append(order, key)
		}
		buckets[key] = append(buckets[key], token)
	}
	for _, token := range strings.Fields(rules) {
		add(ruleBucket(token), token)
	}
	// Порядок видов фиксируем явно: он не должен зависеть от того, какой
	// токен встретился в правилах первым.
	sort.SliceStable(order, func(i, j int) bool {
		return bucketRank(order[i]) < bucketRank(order[j])
	})
	out := make([]adapter.PermissionDetail, 0, len(order))
	for _, key := range order {
		out = append(out, adapter.PermissionDetail{
			Key:   key,
			Value: strings.Join(buckets[key], " "),
		})
	}
	return out
}

// bundleCaveats добавляет к описанию bundle оговорку о том, чего нельзя
// понять из его имени.
//
// Bundle write НЕ означает «писать, не читая»: категория Redis @write
// содержит команды, возвращающие текущее значение (GETSET, GETDEL, LPOP,
// RPOP, SPOP, RENAME, `SET ... GET`). Ограничение на чтение через выдачу
// только write недостижимо в модели категорий Redis, поэтому оговорка
// показывается прямо в карточке права: оператор обязан видеть это ДО выдачи,
// а не узнавать постфактум.
func bundleCaveats(name string) []adapter.PermissionDetail {
	if name != bundleWrite {
		return nil
	}
	return []adapter.PermissionDetail{{
		Key: bucketCaveat,
		Value: "@write includes read-modify-write commands (GETSET, GETDEL, LPOP, RPOP, SPOP, RENAME, " +
			"SET ... GET): this bundle also exposes current values",
	}}
}

// Виды токенов ACL. Значения — ключи деталей, подписи подбирает UI.
const (
	bucketKeyPatterns = "key_patterns"
	bucketChannels    = "channels"
	bucketCategories  = "categories"
	bucketCommands    = "commands"
	bucketSelectors   = "selectors"
	bucketOther       = "other_rules"
	// bucketCaveat — не токен правил, а оговорка о семантике bundle
	// (см. bundleCaveats). Идёт последней деталью.
	bucketCaveat = "caveat"
)

// ruleBucket классифицирует токен ACL по его префиксу.
func ruleBucket(token string) string {
	switch {
	case strings.HasPrefix(token, "~"), strings.HasPrefix(token, "%"):
		return bucketKeyPatterns
	case strings.HasPrefix(token, "&"):
		return bucketChannels
	case strings.HasPrefix(token, "+@"), strings.HasPrefix(token, "-@"):
		return bucketCategories
	case strings.HasPrefix(token, "+"), strings.HasPrefix(token, "-"):
		return bucketCommands
	case strings.HasPrefix(token, "("), strings.HasSuffix(token, ")"):
		return bucketSelectors
	default:
		return bucketOther
	}
}

// bucketRank задаёт порядок видов: от «что доступно» к «как ограничено».
func bucketRank(key string) int {
	switch key {
	case bucketKeyPatterns:
		return 0
	case bucketChannels:
		return 1
	case bucketCategories:
		return 2
	case bucketCommands:
		return 3
	case bucketSelectors:
		return 4
	default:
		return 5
	}
}
