package postgres

import (
	"sort"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав PostgreSQL. Вынесено отдельным файлом: contract-часть
// (adapter.PermissionNormalizer) не связана с discovery в discover.go.
//
// Членства ролей и прямые объектные ACL имеют разные категории, чтобы
// назначение роли не смешивалось с точечной привилегией на объект.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// dangerousRoleFlags — флаги, из-за которых роль считается опасной, с
// объяснением. Порядок фиксирован: от самого широкого к менее широкому.
// Набор обязан совпадать с roleInfo.dangerous — иначе объяснение разойдётся
// с флагом.
var dangerousRoleFlags = []struct {
	attr   string
	reason string
}{
	{"superuser", "superuser: bypasses all permission checks"},
	{"createrole", "can create and alter roles, including granting itself membership"},
	{"replication", "can start replication and read the whole cluster state"},
	{"bypassrls", "bypasses row level security policies"},
}

// NormalizePermission объясняет нотацию прав PostgreSQL.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	if p, err := adapter.ParsePostgresObjectPrivilege(ref.ExternalID); err == nil {
		reason := ""
		switch p.Privilege {
		case "CREATE":
			reason = "allows creating objects in the selected database or schema"
		case "TRIGGER":
			reason = "allows attaching triggers to the selected table"
		case "TRUNCATE":
			reason = "allows removing all rows from the selected table"
		}
		return adapter.PermissionView{Category: adapter.PermissionPrivilege, Action: p.Privilege, Resource: p.Label(), Scope: p.Database,
			Raw: p.Privilege + " ON " + p.Label(), Dangerous: ref.Dangerous, DangerReason: reason, Details: []adapter.PermissionDetail{
				{Key: "object_kind", Value: p.Kind}, {Key: "source", Value: "direct ACL"},
			}}
	}
	return adapter.PermissionView{
		Category: adapter.PermissionRole,
		// Ресурс роли — она сама: выдаётся именно членство в роли.
		Resource:     ref.Name,
		Scope:        ref.ScopeName,
		Dangerous:    ref.Dangerous,
		DangerReason: roleDangerReason(ref),
		Details:      roleFlagDetails(ref.Attributes),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// roleDangerReason перечисляет установленные опасные флаги роли. Если движок
// пометил роль опасной, а флагов в атрибутах нет (историческая запись до
// появления атрибутов), причина остаётся общей — врать про конкретный флаг
// хуже, чем сказать обобщённо.
func roleDangerReason(ref adapter.PermissionRef) string {
	if !ref.Dangerous {
		return ""
	}
	reasons := make([]string, 0, len(dangerousRoleFlags))
	for _, f := range dangerousRoleFlags {
		if adapter.AttrBool(ref.Attributes, f.attr) {
			reasons = append(reasons, f.reason)
		}
	}
	if len(reasons) == 0 {
		return "the engine marks this role as dangerous"
	}
	return strings.Join(reasons, "; ")
}

// roleFlagDetails показывает только установленные флаги: строка
// «superuser: false» ничего не сообщает и лишь удлиняет панель.
func roleFlagDetails(attrs map[string]any) []adapter.PermissionDetail {
	keys := make([]string, 0, len(attrs))
	for k, v := range attrs {
		if b, ok := v.(bool); ok && b {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]adapter.PermissionDetail, 0, len(keys))
	for _, k := range keys {
		out = append(out, adapter.PermissionDetail{Key: k, Value: "true"})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
