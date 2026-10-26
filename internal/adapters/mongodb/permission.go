package mongodb

import (
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав MongoDB. Право — роль, всегда привязанная к базе:
// `readWrite` в базе ads и `readWrite` в базе billing — разные права, и без
// показанной базы подпись роли неоднозначна. База берётся из атрибута
// role_db, а не из scope-ресурса: scope есть не у всех записей (роль
// служебной базы admin не всегда попадает в инвентарь ресурсов), тогда как
// role_db адаптер проставляет всегда.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// NormalizePermission объясняет нотацию прав MongoDB.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	roleDB := adapter.AttrString(ref.Attributes, "role_db")
	scope := ref.ScopeName
	if scope == "" {
		scope = roleDB
	}
	return adapter.PermissionView{
		Category:     adapter.PermissionRole,
		Resource:     ref.Name,
		Scope:        scope,
		Dangerous:    ref.Dangerous,
		DangerReason: roleDangerReason(ref),
		Details:      roleDetails(ref.Attributes),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// roleDangerReason объясняет опасность встроенной роли. Список опасных ролей
// фиксирован (dangerousRoleNames), поэтому проверяем принадлежность к нему;
// пользовательская роль может быть помечена опасной по своим привилегиям.
func roleDangerReason(ref adapter.PermissionRef) string {
	if !ref.Dangerous {
		return ""
	}
	if dangerousRole(ref.Name) {
		return "built-in administrative role: " + ref.Name
	}
	return "the role inherits administrative privileges"
}

// roleDetails показывает происхождение роли и унаследованные роли: без них
// непонятно, откуда у роли права, которых нет в её имени.
func roleDetails(attrs map[string]any) []adapter.PermissionDetail {
	out := make([]adapter.PermissionDetail, 0, 3)
	if db := adapter.AttrString(attrs, "role_db"); db != "" {
		out = append(out, adapter.PermissionDetail{Key: "role_db", Value: db})
	}
	if adapter.AttrBool(attrs, "builtin") {
		out = append(out, adapter.PermissionDetail{Key: "builtin", Value: "true"})
	}
	if inherited := adapter.AttrStrings(attrs, "inherited_roles"); len(inherited) > 0 {
		out = append(out, adapter.PermissionDetail{
			Key:   "inherited_roles",
			Value: strings.Join(inherited, ", "),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
