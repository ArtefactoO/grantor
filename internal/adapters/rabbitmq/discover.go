package rabbitmq

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

// apiOverview — сокращённый ответ GET /api/overview.
type apiOverview struct {
	RabbitMQVersion string `json:"rabbitmq_version"`
	ManagementVer   string `json:"management_version"`
	ClusterName     string `json:"cluster_name"`
	Node            string `json:"node"`
}

// apiWhoami — ответ GET /api/whoami. tags может прийти массивом (новые версии)
// или строкой через запятую (старые), поэтому хранится как RawMessage.
type apiWhoami struct {
	Name string          `json:"name"`
	Tags json.RawMessage `json:"tags"`
}

// apiNode — элемент ответа GET /api/nodes.
type apiNode struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Running bool   `json:"running"`
}

// apiVhost — элемент ответа GET /api/vhosts.
type apiVhost struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	DefaultType string `json:"default_queue_type"`
}

// apiUser — элемент ответа GET /api/users и GET /api/users/{name}. tags может
// прийти массивом или строкой (см. apiWhoami).
type apiUser struct {
	Name             string          `json:"name"`
	Tags             json.RawMessage `json:"tags"`
	PasswordHash     string          `json:"password_hash"`
	HashingAlgorithm string          `json:"hashing_algorithm"`
}

// apiPermission — элемент ответа GET /api/permissions и
// GET /api/users/{name}/permissions.
type apiPermission struct {
	User      string `json:"user"`
	Vhost     string `json:"vhost"`
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

// Discover выполняет полную инвентаризацию: топология (nodes), vhosts, users
// (с тегами), permissions. Все запросы читают только метаданные; мутаций
// discovery не выполняет.
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	templates, err := configuredTemplates(cfg)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}
	client, err := a.newClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}

	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: time.Now(),
	}

	var overview apiOverview
	if _, err := client.getJSON(ctx, "/api/overview", &overview); err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}
	snap.ServerVersion = overview.RabbitMQVersion

	var nodes []apiNode
	if _, err := client.getJSON(ctx, "/api/nodes", &nodes); err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}
	snap.Topology = topologyFromNodes(nodes, overview)

	var vhosts []apiVhost
	if _, err := client.getJSON(ctx, "/api/vhosts", &vhosts); err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}
	vhostSet := make(map[string]bool, len(vhosts))
	for _, v := range vhosts {
		vhostSet[v.Name] = true
		snap.Resources = append(snap.Resources, vhostResource(v))
	}

	snap.Permissions = buildPermissions(vhosts, templates)

	var users []apiUser
	if _, err := client.getJSON(ctx, "/api/users", &users); err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}
	userSet := make(map[string]bool, len(users))
	for _, u := range users {
		if u.Name == "" {
			continue
		}
		userSet[u.Name] = true
		account, bindings := userToObserved(u)
		snap.Accounts = append(snap.Accounts, account)
		snap.Bindings = append(snap.Bindings, bindings...)
	}

	var permissions []apiPermission
	if _, err := client.getJSON(ctx, "/api/permissions", &permissions); err != nil {
		return nil, fmt.Errorf("rabbitmq: discover: %w", err)
	}
	for _, p := range permissions {
		// Binding создаётся только когда и user, и vhost присутствуют в
		// инвентаре: иначе binding сослался бы на несуществующий account или
		// scope (contract suite проверяет консистентность).
		if !userSet[p.User] || !vhostSet[p.Vhost] {
			continue
		}
		snap.Bindings = append(snap.Bindings, vhostBinding(p, templates))
	}
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)

	sortSnapshot(snap)
	return snap, nil
}

// topologyFromNodes определяет тип топологии по числу узлов: один узел —
// standalone, несколько — cluster. Список имён узлов и cluster_name
// добавляются для наглядности.
func topologyFromNodes(nodes []apiNode, overview apiOverview) map[string]any {
	names := make([]string, 0, len(nodes))
	running := 0
	for _, n := range nodes {
		if n.Name != "" {
			names = append(names, n.Name)
		}
		if n.Running {
			running++
		}
	}
	slices.Sort(names)

	topology := "standalone"
	if len(nodes) > 1 {
		topology = "cluster"
	}
	out := map[string]any{
		adapterutil.TopologyKey: topology,
		"node_count":            len(nodes),
		"running_nodes":         running,
	}
	if len(names) > 0 {
		out["nodes"] = names
	}
	if overview.ClusterName != "" {
		out["cluster_name"] = overview.ClusterName
	}
	return out
}

// buildPermissions публикует cluster-wide tags, legacy full access каждого
// vhost, monitoring visibility и configured templates, чей vhost существует.
func buildPermissions(vhosts []apiVhost, configured ...[]rabbitmqconfig.PermissionTemplate) []adapter.ObservedPermission {
	var templates []rabbitmqconfig.PermissionTemplate
	if len(configured) > 0 {
		templates = configured[0]
	}
	out := make([]adapter.ObservedPermission, 0, len(knownTags)+2*len(vhosts)+len(templates))
	for _, tag := range knownTags {
		out = append(out, adapter.ObservedPermission{
			ExternalID: tagPermissionID(tag),
			Name:       "tag:" + tag,
			Assignable: true,
			Dangerous:  dangerousTag(tag),
			Attributes: map[string]any{
				"kind": "tag",
				"tag":  tag,
			},
		})
	}
	for _, v := range vhosts {
		out = append(out, adapter.ObservedPermission{
			ExternalID:      vhostPermissionID(v.Name),
			Name:            "vhost-access:" + v.Name,
			ScopeExternalID: vhostExternalID(v.Name),
			AssignmentKey:   vhostAssignmentKey(v.Name),
			Assignable:      true,
			// Опасной не считается. Полный доступ внутри одного vhost — это
			// базовый рабочий доступ приложения к RabbitMQ, а не эскалация:
			// он не даёт ни контроля над кластером, ни доступа к другим
			// vhost, ни права раздавать доступ (это тег administrator, он и
			// помечен опасным). Калибровка та же, что у остальных движков:
			// опасно то, что ведёт к управлению сервером или чужим доступом,
			// а не то, что разрушительно в своей области.
			//
			// Пока признак был константой true, ни один доступ к vhost не мог
			// быть выдан ролью operator — то есть гейт блокировал ровно тот
			// сценарий, ради которого движок подключают. Ширина при этом не
			// скрыта: атрибут broad_configure виден в карточке права.
			Dangerous: false,
			Attributes: map[string]any{
				"kind":            "vhost",
				"vhost":           v.Name,
				"configure":       fullAccessRegex,
				"write":           fullAccessRegex,
				"read":            fullAccessRegex,
				"broad":           true,
				"broad_configure": isBroadConfigure(fullAccessRegex),
			},
		})
		// Preserve the identity and approval policy of an existing deny-all
		// template instead of publishing another permission for the same tuple.
		if _, configured := matchTemplate(templates, monitoringTuple(v.Name)); !configured {
			out = append(out, adapter.ObservedPermission{
				ExternalID:      vhostMonitoringPermissionID(v.Name),
				Name:            vhostMonitoringPermissionID(v.Name),
				ScopeExternalID: vhostExternalID(v.Name),
				AssignmentKey:   vhostAssignmentKey(v.Name),
				Assignable:      true,
				Dangerous:       false,
				Attributes: map[string]any{
					"kind": "vhost", "vhost": v.Name,
					"configure": monitoringRegex, "write": monitoringRegex, "read": monitoringRegex,
					"broad": false, "broad_configure": false,
				},
			})
		}
	}
	vhostSet := make(map[string]struct{}, len(vhosts))
	for _, vhost := range vhosts {
		vhostSet[vhost.Name] = struct{}{}
	}
	for _, template := range templates {
		if _, exists := vhostSet[template.Vhost]; !exists {
			continue
		}
		out = append(out, adapter.ObservedPermission{
			ExternalID:      templatePermissionID(template.Key),
			Name:            template.Name,
			ScopeExternalID: vhostExternalID(template.Vhost),
			AssignmentKey:   vhostAssignmentKey(template.Vhost),
			Assignable:      true,
			Dangerous:       template.Dangerous,
			Attributes: map[string]any{
				"kind": "vhost", "vhost": template.Vhost,
				"template_key": template.Key, "description": template.Description,
				"configure": template.Configure, "write": template.Write, "read": template.Read,
				"broad":           rabbitmqconfig.IsBroad(template),
				"broad_configure": isBroadConfigure(template.Configure),
			},
		})
	}
	return out
}

// userToObserved превращает пользователя в аккаунт и его bindings по тегам.
// Аккаунт считается disabled, если у него есть служебный маркер
// grantor_disabled. Binding создаётся только для функциональных тегов
// (knownTags): для них существует permission-определение.
func userToObserved(u apiUser) (adapter.ObservedAccount, []adapter.ObservedBinding) {
	tags := parseTags(u.Tags)
	functional := functionalTags(tags)

	account := adapter.ObservedAccount{
		Kind:           "login",
		EngineIdentity: u.Name,
		Disabled:       hasTag(tags, disabledMarkerTag),
		Attributes: map[string]any{
			"tags": functional,
		},
	}

	var bindings []adapter.ObservedBinding
	for _, tag := range functional {
		bindings = append(bindings, adapter.ObservedBinding{
			AccountEngineIdentity: u.Name,
			PermissionExternalID:  tagPermissionID(tag),
			Attributes:            map[string]any{"tag": tag},
		})
	}
	return account, bindings
}

// vhostBinding строит binding пользователя к vhost-permission с наблюдаемыми
// regex-ами в атрибутах.
//
// Exact tuples match legacy full access, then configured templates, then
// builtin monitoring visibility. Existing template IDs retain precedence.
// Неизвестная тройка остаётся наблюдаемой в legacy assignment slot, но получает
// template_matched=false/effective=false, поэтому managed binding виден drift,
// а не ложным synced.
func vhostBinding(p apiPermission, configured ...[]rabbitmqconfig.PermissionTemplate) adapter.ObservedBinding {
	var templates []rabbitmqconfig.PermissionTemplate
	if len(configured) > 0 {
		templates = configured[0]
	}
	permissionID := vhostPermissionID(p.Vhost)
	matched := isFullAccess(p)
	if !matched {
		if template, ok := matchTemplate(templates, apiPermissionTuple(p)); ok {
			permissionID = templatePermissionID(template.Key)
			matched = true
		} else if tupleMatches(p, monitoringTuple(p.Vhost)) {
			permissionID = vhostMonitoringPermissionID(p.Vhost)
			matched = true
		}
	}
	return adapter.ObservedBinding{
		AccountEngineIdentity: p.User,
		PermissionExternalID:  permissionID,
		ScopeExternalID:       vhostExternalID(p.Vhost),
		AssignmentKey:         vhostAssignmentKey(p.Vhost),
		Attributes: map[string]any{
			"configure":                  p.Configure,
			"write":                      p.Write,
			"read":                       p.Read,
			"broad_configure":            isBroadConfigure(p.Configure),
			"broad":                      tupleBroad(apiPermissionTuple(p)),
			"template_matched":           matched,
			adapter.AttrBindingEffective: matched,
		},
	}
}

// vhostResource строит ресурс kind vhost.
func vhostResource(v apiVhost) adapter.ObservedResource {
	attrs := map[string]any{}
	if v.Description != "" {
		attrs["description"] = v.Description
	}
	if v.DefaultType != "" {
		attrs["default_queue_type"] = v.DefaultType
	}
	id := vhostExternalID(v.Name)
	return adapter.ObservedResource{
		Kind:          "vhost",
		ExternalID:    id,
		Name:          v.Name,
		CanonicalPath: v.Name,
		Attributes:    attrs,
		Fingerprint:   fingerprint("vhost", id, attrs),
	}
}

// fullAccessRegex — regex полного доступа RabbitMQ (совпадает со всеми
// именами очередей/exchange в vhost).
const fullAccessRegex = ".*"

// monitoringRegex admits the vhost without authorizing queue/exchange actions.
const monitoringRegex = "^$"

// isBroadConfigure сообщает, является ли configure-regex «широким», то есть
// дающим права configure на все объекты vhost (создание/удаление очередей,
// exchange, policies). Таким считается ".*".
func isBroadConfigure(configure string) bool {
	return configure == fullAccessRegex
}

// dangerousTag сообщает, даёт ли тег привилегии, требующие особого контроля.
// Опасен только administrator (полный контроль над кластером и всеми vhost).
func dangerousTag(tag string) bool {
	return tag == tagAdministrator
}

// functionalTags возвращает подмножество тегов, входящих в knownTags,
// в детерминированном порядке. Служебный маркер и custom-теги отбрасываются.
func functionalTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range knownTags {
		if hasTag(tags, tag) {
			out = append(out, tag)
		}
	}
	return out
}

// parseTags разбирает поле tags Management API: массив строк (новые версии)
// либо строку через запятую (старые версии). Пустые элементы отбрасываются.
func parseTags(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return cleanTags(list)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return cleanTags(strings.Split(s, ","))
	}
	return nil
}

// cleanTags убирает пробелы по краям и пустые элементы.
func cleanTags(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// hasTag сообщает, присутствует ли тег в наборе.
func hasTag(tags []string, tag string) bool {
	return slices.Contains(tags, tag)
}

// Префиксы external id permission-определений. tag-permission и
// vhost-permission живут в разных пространствах, чтобы не пересекаться между
// собой и с external id vhost-ресурса ("vhost:").
const (
	tagPermissionPrefix             = "tag:"
	vhostPermissionPrefix           = "vhost-access:"
	vhostMonitoringPermissionPrefix = "vhost-monitoring:"
)

// vhostExternalID возвращает external id vhost-ресурса.
func vhostExternalID(name string) string { return "vhost:" + name }

// tagPermissionID возвращает external id tag-permission.
func tagPermissionID(tag string) string { return tagPermissionPrefix + tag }

// vhostPermissionID возвращает external id vhost-permission.
func vhostPermissionID(vhost string) string { return vhostPermissionPrefix + vhost }

func vhostMonitoringPermissionID(vhost string) string {
	return vhostMonitoringPermissionPrefix + vhost
}

// fingerprint строит стабильный отпечаток ресурса по kind, external id и
// атрибутам. Ключи атрибутов сортируются, а значения кодируются каноничным
// JSON, поэтому одно и то же содержимое всегда даёт один и тот же отпечаток
// независимо от порядка map.
func fingerprint(kind, externalID string, attrs map[string]any) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(attrs)+2)
	parts = append(parts, kind, externalID)
	for _, k := range keys {
		enc, err := json.Marshal(attrs[k])
		if err != nil {
			enc = []byte(fmt.Sprintf("%v", attrs[k]))
		}
		parts = append(parts, k+"="+string(enc))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])[:16]
}

// sortSnapshot приводит snapshot к детерминированному порядку: contract suite
// требует стабильности между повторными discovery.
func sortSnapshot(snap *adapter.Snapshot) {
	slices.SortFunc(snap.Resources, func(a, b adapter.ObservedResource) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	slices.SortFunc(snap.Accounts, func(a, b adapter.ObservedAccount) int {
		return strings.Compare(a.EngineIdentity, b.EngineIdentity)
	})
	slices.SortFunc(snap.Permissions, func(a, b adapter.ObservedPermission) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	slices.SortFunc(snap.Bindings, func(a, b adapter.ObservedBinding) int {
		if c := strings.Compare(a.AccountEngineIdentity, b.AccountEngineIdentity); c != 0 {
			return c
		}
		if c := strings.Compare(a.PermissionExternalID, b.PermissionExternalID); c != 0 {
			return c
		}
		return strings.Compare(a.ScopeExternalID, b.ScopeExternalID)
	})
}
