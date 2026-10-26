package rabbitmq

import (
	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав RabbitMQ. Движок даёт два несводимых вида прав:
//
//   - серверный тег пользователя (kind=tag, имя `tag:<tag>`) — влияет на
//     доступ к management API и административным действиям;
//   - доступ к vhost (kind=vhost, имя `vhost-access:<vhost>`) — тройка
//     регулярных выражений configure/write/read внутри одного vhost.
//
// Для vhost важны именно три регулярки: право «configure .*» означает
// возможность создавать и удалять объекты, и это принципиально шире, чем
// чтение. Поэтому они выносятся в details, а не сворачиваются в одну строку.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// NormalizePermission объясняет нотацию прав RabbitMQ.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	switch adapter.AttrString(ref.Attributes, "kind") {
	case "tag":
		return a.normalizeTag(ref)
	case "vhost":
		return a.normalizeVhost(ref)
	default:
		return adapter.GenericPermissionView(ref)
	}
}

// normalizeTag разбирает серверный тег пользователя.
func (a *Adapter) normalizeTag(ref adapter.PermissionRef) adapter.PermissionView {
	tag := adapter.AttrString(ref.Attributes, "tag")
	return adapter.PermissionView{
		Category:     adapter.PermissionTag,
		Resource:     tag,
		Dangerous:    ref.Dangerous,
		DangerReason: tagDangerReason(ref.Dangerous, tag),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// normalizeVhost разбирает доступ к vhost.
func (a *Adapter) normalizeVhost(ref adapter.PermissionRef) adapter.PermissionView {
	vhost := adapter.AttrString(ref.Attributes, "vhost")
	return adapter.PermissionView{
		Category:     adapter.PermissionVhost,
		Resource:     vhost,
		Scope:        vhost,
		Dangerous:    ref.Dangerous,
		DangerReason: vhostDangerReason(ref),
		Details:      append(vhostDetails(ref.Attributes), vhostCaveats(ref.Attributes)...),
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// tagDangerReason объясняет опасность тега: административные теги дают
// доступ к management API и управлению пользователями.
func tagDangerReason(dangerous bool, tag string) string {
	if !dangerous {
		return ""
	}
	return "administrative tag: " + tag
}

// vhostDangerReason объясняет опасность доступа к vhost, если движок её
// объявил. Полный доступ внутри vhost сам по себе опасным не считается
// (см. buildPermissions), поэтому обычный путь — пустая причина.
func vhostDangerReason(ref adapter.PermissionRef) string {
	if !ref.Dangerous {
		return ""
	}
	if adapter.AttrBool(ref.Attributes, "broad_configure") {
		return "broad configure permission: allows creating and deleting objects in the vhost"
	}
	return "the engine marks this vhost permission as dangerous"
}

// vhostCaveats показывает ширину доступа отдельной строкой. Право не опасно
// в смысле эскалации, но оператор обязан видеть, что configure ".*" — это
// создание и удаление объектов во всём vhost, а не только работа с
// существующими очередями.
func vhostCaveats(attrs map[string]any) []adapter.PermissionDetail {
	if !adapter.AttrBool(attrs, "broad_configure") {
		return nil
	}
	return []adapter.PermissionDetail{{
		Key:   "caveat",
		Value: `configure ".*" allows creating and deleting queues, exchanges and bindings in the whole vhost`,
	}}
}

// vhostDetails показывает три регулярки доступа в фиксированном порядке
// configure/write/read — том же, в котором их показывает сам RabbitMQ.
func vhostDetails(attrs map[string]any) []adapter.PermissionDetail {
	out := make([]adapter.PermissionDetail, 0, 3)
	for _, key := range []string{"configure", "write", "read"} {
		if v := adapter.AttrString(attrs, key); v != "" {
			out = append(out, adapter.PermissionDetail{Key: key, Value: v})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
