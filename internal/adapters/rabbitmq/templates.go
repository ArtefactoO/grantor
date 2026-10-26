package rabbitmq

import (
	"fmt"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

const templatePermissionPrefix = "rabbitmq-template:"

type permissionTuple struct {
	Vhost     string
	Configure string
	Write     string
	Read      string
}

func configuredTemplates(cfg adapter.Connection) ([]rabbitmqconfig.PermissionTemplate, error) {
	templates, err := rabbitmqconfig.FromAttributes(cfg.Attributes)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: permission templates: %w", err)
	}
	return templates, nil
}

func templatePermissionID(key string) string { return templatePermissionPrefix + key }

func vhostAssignmentKey(vhost string) string { return "rabbitmq:vhost:" + vhost }

func findTemplateByKey(templates []rabbitmqconfig.PermissionTemplate, key string) (rabbitmqconfig.PermissionTemplate, bool) {
	for _, template := range templates {
		if template.Key == key {
			return template, true
		}
	}
	return rabbitmqconfig.PermissionTemplate{}, false
}

func matchTemplate(templates []rabbitmqconfig.PermissionTemplate, actual permissionTuple) (rabbitmqconfig.PermissionTemplate, bool) {
	for _, template := range templates {
		if templateTuple(template) == actual {
			return template, true
		}
	}
	return rabbitmqconfig.PermissionTemplate{}, false
}

func templateTuple(template rabbitmqconfig.PermissionTemplate) permissionTuple {
	return permissionTuple{
		Vhost: template.Vhost, Configure: template.Configure,
		Write: template.Write, Read: template.Read,
	}
}

func apiPermissionTuple(permission apiPermission) permissionTuple {
	return permissionTuple{
		Vhost: permission.Vhost, Configure: permission.Configure,
		Write: permission.Write, Read: permission.Read,
	}
}

func monitoringTuple(vhost string) permissionTuple {
	return permissionTuple{Vhost: vhost, Configure: monitoringRegex, Write: monitoringRegex, Read: monitoringRegex}
}

func permissionTarget(change adapter.DesiredChange) (permissionTuple, bool, error) {
	if key, ok := strings.CutPrefix(change.Permission, templatePermissionPrefix); ok {
		if key == "" {
			return permissionTuple{}, false, fmt.Errorf("permission %q has empty template key", change.Permission)
		}
		if pinned, present, err := pinnedTemplate(change.Attributes, key); present || err != nil {
			if err != nil {
				return permissionTuple{}, false, err
			}
			return templateTuple(pinned), true, nil
		}
		// Compatibility fallback for adapter-native callers and older tests. The
		// operation pipeline pins template attributes before enqueue so retries do
		// not reinterpret the same key through a newer connection catalog.
		templates, err := configuredTemplates(change.Connection)
		if err != nil {
			return permissionTuple{}, false, err
		}
		template, found := findTemplateByKey(templates, key)
		if !found {
			return permissionTuple{}, false, fmt.Errorf("permission template %q is not configured: %w", key, adapter.ErrUnsupportedChange)
		}
		return templateTuple(template), true, nil
	}
	kind, value, err := parsePermission(change.Permission)
	if err != nil {
		return permissionTuple{}, false, err
	}
	if kind != permKindVhost {
		return permissionTuple{}, false, fmt.Errorf("permission %q is not a vhost permission: %w", change.Permission, adapter.ErrUnsupportedChange)
	}
	if strings.HasPrefix(change.Permission, vhostMonitoringPermissionPrefix) {
		// The builtin tuple cannot be widened through supplied operation attrs.
		return monitoringTuple(value), false, nil
	}
	return permissionTuple{Vhost: value, Configure: fullAccessRegex, Write: fullAccessRegex, Read: fullAccessRegex}, false, nil
}

func pinnedTemplate(attributes map[string]any, expectedKey string) (rabbitmqconfig.PermissionTemplate, bool, error) {
	value, present := attributes["template_key"]
	if !present {
		return rabbitmqconfig.PermissionTemplate{}, false, nil
	}
	key, ok := value.(string)
	if !ok || key != expectedKey {
		return rabbitmqconfig.PermissionTemplate{}, true, fmt.Errorf(
			"pinned template key does not match permission %q", expectedKey)
	}
	readString := func(field string) (string, error) {
		value, ok := attributes[field].(string)
		if !ok || value == "" {
			return "", fmt.Errorf("pinned template %q has invalid %s", expectedKey, field)
		}
		return value, nil
	}
	vhost, err := readString("vhost")
	if err != nil {
		return rabbitmqconfig.PermissionTemplate{}, true, err
	}
	configure, err := readString("configure")
	if err != nil {
		return rabbitmqconfig.PermissionTemplate{}, true, err
	}
	write, err := readString("write")
	if err != nil {
		return rabbitmqconfig.PermissionTemplate{}, true, err
	}
	read, err := readString("read")
	if err != nil {
		return rabbitmqconfig.PermissionTemplate{}, true, err
	}
	template := rabbitmqconfig.PermissionTemplate{
		Key: expectedKey, Name: "pinned", Description: "pinned operation template",
		Vhost: vhost, Configure: configure, Write: write, Read: read,
	}
	if err := rabbitmqconfig.Validate([]rabbitmqconfig.PermissionTemplate{template}); err != nil {
		return rabbitmqconfig.PermissionTemplate{}, true, fmt.Errorf("invalid pinned template %q: %w", expectedKey, err)
	}
	return template, true, nil
}

func tupleMatches(permission apiPermission, target permissionTuple) bool {
	return apiPermissionTuple(permission) == target
}

func tupleBroad(tuple permissionTuple) bool {
	return tuple.Configure == fullAccessRegex || tuple.Write == fullAccessRegex || tuple.Read == fullAccessRegex
}
