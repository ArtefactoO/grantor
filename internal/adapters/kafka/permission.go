package kafka

import (
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Нормализация прав Kafka/Redpanda. Движок даёт два вида прав:
//
//   - назначаемый bundle (kind=bundle) — набор операций, который grantor
//     выдаёт как единое право: produce/consume на топик, cluster-admin;
//   - наблюдаемая ACL-запись (kind=acl) — одна строка ACL кластера,
//     пятёрка resource type / pattern / resource name / operation /
//     permission.
//
// Разбирать имя `acl:<type>:<pattern>:<name>:<operation>:<permission>` не
// требуется: адаптер кладёт все пять полей в атрибуты. Это существенно —
// имя ресурса Kafka может содержать символы, по которым разбор строки
// становится неоднозначным.

var _ adapter.PermissionNormalizer = (*Adapter)(nil)

// NormalizePermission объясняет нотацию прав Kafka.
func (a *Adapter) NormalizePermission(ref adapter.PermissionRef) adapter.PermissionView {
	switch adapter.AttrString(ref.Attributes, "kind") {
	case "acl":
		return a.normalizeACL(ref)
	case "bundle":
		return a.normalizeBundle(ref)
	default:
		return adapter.GenericPermissionView(ref)
	}
}

// normalizeACL разбирает наблюдаемую ACL-запись.
func (a *Adapter) normalizeACL(ref adapter.PermissionRef) adapter.PermissionView {
	attrs := ref.Attributes
	resourceType := adapter.AttrString(attrs, "resource_type")
	resourceName := adapter.AttrString(attrs, "resource_name")
	operation := adapter.AttrString(attrs, "operation")
	pattern := adapter.AttrString(attrs, "pattern")
	permission := adapter.AttrString(attrs, "permission")

	details := make([]adapter.PermissionDetail, 0, 4)
	appendDetail := func(key, value string) {
		if value != "" {
			details = append(details, adapter.PermissionDetail{Key: key, Value: value})
		}
	}
	appendDetail("resource_type", resourceType)
	appendDetail("pattern", pattern)
	appendDetail("permission", permission)
	appendDetail("host", adapter.AttrString(attrs, "host"))

	return adapter.PermissionView{
		Category:     adapter.PermissionACL,
		Action:       operation,
		Resource:     resourceName,
		Scope:        ref.ScopeName,
		Dangerous:    ref.Dangerous,
		DangerReason: aclDangerReason(ref.Dangerous, resourceType, operation, resourceName),
		Details:      details,
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// normalizeBundle разбирает назначаемый набор операций.
func (a *Adapter) normalizeBundle(ref adapter.PermissionRef) adapter.PermissionView {
	attrs := ref.Attributes
	topic := adapter.AttrString(attrs, "topic")
	cluster := adapter.AttrString(attrs, "cluster")
	operations := adapter.AttrStrings(attrs, "operations")

	category := adapter.PermissionTopic
	resource := topic
	if topic == "" {
		// Bundle без топика — кластерный (cluster-admin).
		category = adapter.PermissionBundle
		resource = cluster
	}

	details := make([]adapter.PermissionDetail, 0, 2)
	if len(operations) > 0 {
		details = append(details, adapter.PermissionDetail{
			Key:   "operations",
			Value: strings.Join(operations, ", "),
		})
	}
	if group := adapter.AttrString(attrs, "group"); group != "" {
		details = append(details, adapter.PermissionDetail{Key: "group", Value: group})
	}

	return adapter.PermissionView{
		Category:     category,
		Action:       bundleAction(ref.Name),
		Resource:     resource,
		Scope:        ref.ScopeName,
		Dangerous:    ref.Dangerous,
		DangerReason: bundleDangerReason(ref.Dangerous, operations),
		Details:      details,
		Raw:          adapter.RawPermissionExpression(ref),
	}
}

// bundleAction выводит действие из имени bundle. Это единственное место, где
// разбирается имя: у bundle нет атрибута с действием, а префиксы заданы
// самим адаптером и потому надёжны.
func bundleAction(name string) string {
	switch {
	case strings.HasPrefix(name, producePermissionPrefix):
		return "write"
	case strings.HasPrefix(name, consumePermissionPrefix):
		return "read"
	case name == clusterAdminPermission:
		return "admin"
	default:
		return ""
	}
}

// aclDangerReason объясняет опасность ACL-записи. Флаг ставится за широкие
// права на кластер и за wildcard-записи (dangerousEntry), поэтому называем
// именно это.
func aclDangerReason(dangerous bool, resourceType, operation, resourceName string) string {
	if !dangerous {
		return ""
	}
	if resourceType == "cluster" {
		return "cluster-wide " + operation + " permission"
	}
	if resourceName == wildcardName {
		return "wildcard " + operation + " permission on every " + resourceType
	}
	return "the engine marks this ACL entry as dangerous"
}

// bundleDangerReason объясняет опасность набора операций.
func bundleDangerReason(dangerous bool, operations []string) string {
	if !dangerous {
		return ""
	}
	if len(operations) == 0 {
		return "the engine marks this permission as dangerous"
	}
	return "grants cluster operations: " + strings.Join(operations, ", ")
}
