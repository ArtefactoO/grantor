package kafka

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотации из discover.go: назначаемые bundle (`topic-produce:<topic>`,
// `topic-consume:<topic>`, cluster-admin) и наблюдаемые ACL-записи.
func TestNormalizePermission(t *testing.T) {
	ad := New()

	t.Run("produce bundle", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: producePermissionPrefix + "orders",
			Name:       producePermissionPrefix + "orders",
			ScopeName:  "orders",
			Assignable: true,
			Attributes: map[string]any{
				"kind": "bundle", "topic": "orders",
				"operations": []string{"WRITE", "DESCRIBE"},
			},
		})
		if view.Category != adapter.PermissionTopic {
			t.Errorf("Category = %q, want topic", view.Category)
		}
		if view.Action != "write" || view.Resource != "orders" {
			t.Errorf("Action/Resource = %q/%q, want write/orders", view.Action, view.Resource)
		}
	})

	t.Run("cluster admin bundle", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: clusterAdminPermission,
			Name:       clusterAdminPermission,
			Assignable: true,
			Dangerous:  true,
			Attributes: map[string]any{
				"kind": "bundle", "cluster": clusterResourceName,
				"operations": []string{"ALL"},
			},
		})
		if view.Action != "admin" {
			t.Errorf("Action = %q, want admin", view.Action)
		}
		if view.Resource != clusterResourceName {
			t.Errorf("Resource = %q, want the cluster", view.Resource)
		}
	})

	// Пять полей ACL берутся из атрибутов: разбирать имя по ':' нельзя —
	// имя ресурса Kafka может содержать двоеточие.
	t.Run("acl entry is read from attributes", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "acl:topic:literal:orders:read:allow",
			Name:       "acl:topic:literal:orders:read:allow",
			Attributes: map[string]any{
				"kind": "acl", "resource_type": "topic", "resource_name": "orders",
				"pattern": "literal", "operation": "read", "permission": "allow",
			},
		})
		if view.Category != adapter.PermissionACL {
			t.Errorf("Category = %q, want acl", view.Category)
		}
		if view.Action != "read" || view.Resource != "orders" {
			t.Errorf("Action/Resource = %q/%q, want read/orders", view.Action, view.Resource)
		}
		keys := make([]string, 0, len(view.Details))
		for _, d := range view.Details {
			keys = append(keys, d.Key)
		}
		if len(keys) < 3 || keys[0] != "resource_type" || keys[1] != "pattern" || keys[2] != "permission" {
			t.Errorf("detail keys = %v, want resource_type/pattern/permission first", keys)
		}
	})

	t.Run("wildcard acl explains the danger", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "acl:topic:literal:*:read:allow",
			Name:       "acl:topic:literal:*:read:allow",
			Dangerous:  true,
			Attributes: map[string]any{
				"kind": "acl", "resource_type": "topic", "resource_name": wildcardName,
				"pattern": "literal", "operation": "read", "permission": "allow",
			},
		})
		want := "wildcard read permission on every topic"
		if view.DangerReason != want {
			t.Errorf("DangerReason = %q, want %q", view.DangerReason, want)
		}
	})

	t.Run("unknown notation degrades", func(t *testing.T) {
		adaptertest.CheckPermissionNormalizationDegrades(t, ad)
	})
}
