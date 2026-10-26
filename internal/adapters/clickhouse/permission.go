package clickhouse

import (
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав ClickHouse. Движок даёт два разных вида прав, которые
// раньше выглядели в UI одинаково:
//
//   - роль (kind=role) — назначаемая, выдаётся grantor;
//   - прямой грант (kind=privilege, имя `<ACCESS TYPE> ON <db>.*`) — только
//     наблюдаемый: adapter выдаёт доступ исключительно через роли.
//
// Разделение важно оператору: у прямого гранта нет кнопки «отозвать» — им
// управляют вне grantor.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// NormalizePermission объясняет нотацию прав ClickHouse.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	if adapter.AttrString(ref.Attributes, "kind") == "privilege" {
		return a.normalizePrivilege(ref)
	}
	return a.normalizeRole(ref)
}

// normalizeRole разбирает назначаемую роль.
func (a *Adapter) normalizeRole(ref adapter.PermissionRef) adapter.PermissionView {
	privs := adapter.AttrStrings(ref.Attributes, "privileges")
	return adapter.PermissionView{
		Category:     adapter.PermissionRole,
		Resource:     ref.Name,
		Scope:        ref.ScopeName,
		Dangerous:    ref.Dangerous,
		DangerReason: roleDangerReason(ref.Dangerous, privs),
		Details:      roleDetails(ref.Attributes, privs),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// normalizePrivilege разбирает прямой грант `<ACCESS TYPE> ON <db>.*`.
// Access type и база берутся из атрибутов; разбор имени не нужен.
func (a *Adapter) normalizePrivilege(ref adapter.PermissionRef) adapter.PermissionView {
	accessType := adapter.AttrString(ref.Attributes, "access_type")
	database := adapter.AttrString(ref.Attributes, "database")
	scope := database
	if scope == "" {
		// Пустая база в атрибутах означает грант на весь кластер (`ON *.*`).
		scope = clusterWideScope
	}
	return adapter.PermissionView{
		Category:     adapter.PermissionPrivilege,
		Action:       accessType,
		Resource:     scope,
		Scope:        scope,
		Dangerous:    ref.Dangerous,
		DangerReason: privilegeDangerReason(ref.Dangerous, accessType, database == ""),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// clusterWideScope — как показывается грант без базы: та же нотация, что и в
// самом ClickHouse.
const clusterWideScope = "*.*"

// roleDangerReason перечисляет опасные привилегии роли. Причина строится из
// того же набора, по которому выставлен флаг (roleDangerous).
func roleDangerReason(dangerous bool, privs []string) string {
	if !dangerous {
		return ""
	}
	flagged := make([]string, 0, len(privs))
	for _, p := range privs {
		if privilegeLooksDangerous(p) {
			flagged = append(flagged, p)
		}
	}
	if len(flagged) == 0 {
		return "the engine marks this role as dangerous"
	}
	return "grants administrative privileges: " + strings.Join(flagged, ", ")
}

// privilegeLooksDangerous проверяет строку гранта роли по тому же признаку,
// что и dangerousAccessType: грант вида `<ACCESS TYPE> ON <db>` разбирается
// до access type, кластерным считается грант на `*.*`.
//
// Хвост после базы отбрасывается: formatGrant добавляет к гранту суффиксы
// вида `WITH GRANT OPTION`, и без этого «*.* WITH GRANT OPTION» не был бы
// распознан как кластерный.
func privilegeLooksDangerous(grant string) bool {
	// Сервера здесь нет: объяснение строится по уже сохранённым атрибутам,
	// поэтому берётся offline-набор (см. staticDangerousPrivileges).
	danger := newDangerSet()
	accessType, database, found := strings.Cut(grant, " ON ")
	if !found {
		return dangerousAccessType(danger, strings.TrimSpace(grant), true)
	}
	db := ""
	if fields := strings.Fields(database); len(fields) > 0 {
		db = fields[0]
	}
	clusterWide := db == "" || db == clusterWideScope
	return dangerousAccessType(danger, strings.TrimSpace(accessType), clusterWide)
}

// privilegeDangerReason объясняет опасность прямого гранта.
func privilegeDangerReason(dangerous bool, accessType string, clusterWide bool) string {
	if !dangerous {
		return ""
	}
	if clusterWide {
		return "cluster-wide grant of " + accessType
	}
	return "administrative privilege: " + accessType
}

// roleDetails показывает состав роли: без списка привилегий имя роли ничего
// не сообщает о том, что она даёт.
func roleDetails(attrs map[string]any, privs []string) []adapter.PermissionDetail {
	out := make([]adapter.PermissionDetail, 0, 2)
	if storage := adapter.AttrString(attrs, "storage"); storage != "" {
		out = append(out, adapter.PermissionDetail{Key: "storage", Value: storage})
	}
	if len(privs) > 0 {
		out = append(out, adapter.PermissionDetail{
			Key:   "privileges",
			Value: strings.Join(privs, ", "),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
