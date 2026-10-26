package rabbitmq

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
)

// Нотации из discover.go: серверный тег (`tag:<tag>`) и доступ к vhost
// (`vhost-access:<vhost>` с тройкой регулярок).
func TestNormalizePermission(t *testing.T) {
	ad := New()

	t.Run("tag", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "tag:administrator",
			Name:       "tag:administrator",
			Assignable: true,
			Dangerous:  true,
			Attributes: map[string]any{"kind": "tag", "tag": "administrator"},
		})
		if view.Category != adapter.PermissionTag {
			t.Errorf("Category = %q, want tag", view.Category)
		}
		if view.Resource != "administrator" {
			t.Errorf("Resource = %q, want the tag itself", view.Resource)
		}
		if view.DangerReason != "administrative tag: administrator" {
			t.Errorf("DangerReason = %q, want the tag named", view.DangerReason)
		}
	})

	// Три регулярки разного смысла: широкий configure означает право
	// создавать и удалять объекты, и сворачивать его в одну строку с read
	// нельзя.
	t.Run("vhost keeps the three regexes apart", func(t *testing.T) {
		view := adaptertest.CheckPermissionNormalization(t, ad, adapter.PermissionRef{
			ExternalID: "vhost-access:project",
			Name:       "vhost-access:project",
			ScopeName:  "project",
			Assignable: true,
			Dangerous:  false,
			Attributes: map[string]any{
				"kind": "vhost", "vhost": "project",
				"configure": ".*", "write": ".*", "read": ".*",
				"broad_configure": true,
			},
		})
		if view.Category != adapter.PermissionVhost {
			t.Errorf("Category = %q, want vhost", view.Category)
		}
		keys := make([]string, 0, len(view.Details))
		for _, d := range view.Details {
			keys = append(keys, d.Key)
		}
		// Право не опасно, но его ширина обязана быть видна отдельной
		// строкой: configure ".*" — это создание и удаление объектов.
		if len(keys) != 4 || keys[0] != "configure" || keys[1] != "write" || keys[2] != "read" || keys[3] != "caveat" {
			t.Errorf("detail keys = %v, want configure/write/read/caveat in that order", keys)
		}
		if view.DangerReason != "" {
			t.Errorf("DangerReason = %q, want empty for a non-dangerous permission", view.DangerReason)
		}
	})

	t.Run("unknown notation degrades", func(t *testing.T) {
		adaptertest.CheckPermissionNormalizationDegrades(t, ad)
	})
}
