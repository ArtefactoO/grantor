package mysql

import (
	"sort"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав MySQL. Право — роль, адресуемая парой user@host
// (userHostIdentity), поэтому host выносится в scope: две роли с одним именем
// и разными host — разные роли, и пользователь обязан это видеть.
//
// Опасность роли определяется её глобальными привилегиями
// (dangerousGlobalPrivileges), поэтому в причине перечисляются ровно те
// привилегии из набора, которые движок считает опасными.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// NormalizePermission объясняет нотацию прав MySQL.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	host := adapter.AttrString(ref.Attributes, "host")
	scope := ref.ScopeName
	if scope == "" {
		scope = host
	}
	return adapter.PermissionView{
		Category: adapter.PermissionRole,
		// Ресурс роли — она сама; имя показываем без host, он ушёл в scope.
		Resource:     roleNameWithoutHost(ref.Name, host),
		Scope:        scope,
		Dangerous:    ref.Dangerous,
		DangerReason: privilegeDangerReason(ref),
		Details:      privilegeDetails(ref.Attributes),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// roleNameWithoutHost отбрасывает суффикс @host, уже показанный в scope.
// Если имя не в форме user@host (историческая запись), возвращается как есть.
func roleNameWithoutHost(name, host string) string {
	if host == "" {
		return name
	}
	suffix := "@" + host
	return strings.TrimSuffix(name, suffix)
}

// privilegeDangerReason перечисляет опасные глобальные привилегии роли.
func privilegeDangerReason(ref adapter.PermissionRef) string {
	if !ref.Dangerous {
		return ""
	}
	privs := adapter.AttrStrings(ref.Attributes, "global_privileges")
	dangerous := make([]string, 0, len(privs))
	for _, p := range privs {
		if dangerousGlobalPrivileges[strings.ToUpper(strings.TrimSpace(p))] {
			dangerous = append(dangerous, strings.ToUpper(strings.TrimSpace(p)))
		}
	}
	if len(dangerous) == 0 {
		return "the engine marks this role as dangerous"
	}
	sort.Strings(dangerous)
	return "grants administrative privileges: " + strings.Join(dangerous, ", ")
}

// privilegeDetails показывает глобальные привилегии роли; host уже выражен
// через scope и здесь не повторяется.
func privilegeDetails(attrs map[string]any) []adapter.PermissionDetail {
	privs := adapter.AttrStrings(attrs, "global_privileges")
	if len(privs) == 0 {
		return nil
	}
	sorted := append([]string(nil), privs...)
	sort.Strings(sorted)
	return []adapter.PermissionDetail{
		{Key: "global_privileges", Value: strings.Join(sorted, ", ")},
	}
}
