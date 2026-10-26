package kafka

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func TestManifest(t *testing.T) {
	m := New().Manifest()
	if m.Engine != Engine {
		t.Errorf("engine = %q, want %q", m.Engine, Engine)
	}
	if m.Version == "" || m.ConnectionSchema == "" {
		t.Error("manifest must set Version and ConnectionSchema")
	}
	for _, want := range []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions, adapter.CapInventoryBindings,
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
		adapter.CapAccountCreate, adapter.CapAccountDisable,
		adapter.CapAccountEnable, adapter.CapAccountDelete,
		adapter.CapCredentialRotate, adapter.CapCredentialProve,
	} {
		if !m.HasCapability(want) {
			t.Errorf("manifest must declare %q", want)
		}
	}
	if !slices.Contains(m.ResourceKinds, "topic") {
		t.Errorf("manifest must declare topic resource kind, got %v", m.ResourceKinds)
	}
}

func TestProveCredentialRequiresScramLifecycle(t *testing.T) {
	cfg := adapter.Connection{
		Endpoints: []string{"127.0.0.1:9092"},
		Attributes: map[string]any{
			attrSASLMechanism:    string(mechPlain),
			attrSecurityProtocol: string(protoSASLPlaintext),
		},
	}
	err := New().ProveCredential(t.Context(), cfg,
		adapter.Account{Kind: "login", EngineIdentity: "service-user"},
		adapter.Credential{Kind: "password", Secret: []byte("password")})
	if !errors.Is(err, adapter.ErrCredentialProofUnsupported) {
		t.Errorf("error = %v, want ErrCredentialProofUnsupported", err)
	}
}

func TestKafkaAuthenticationFailureClassification(t *testing.T) {
	if !isAuthenticationFailure(kerr.SaslAuthenticationFailed) {
		t.Error("SASL authentication failure must be classified explicitly")
	}
	if isAuthenticationFailure(errors.New("authentication failed")) {
		t.Error("error text alone must not be classified as an authentication failure")
	}
}

// TestCapabilitiesForConnection проверяет сужение engine-wide манифеста под
// конкретное подключение: механизм решает судьбу SCRAM-lifecycle, наблюдаемое
// состояние ACL-авторизатора — судьбу ACL-операций, инвентарь остаётся всегда.
func TestCapabilitiesForConnection(t *testing.T) {
	ad := New()
	inventory := []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions, adapter.CapInventoryBindings,
	}
	aclOps := []adapter.Capability{
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
		adapter.CapAccountDisable, adapter.CapAccountEnable,
	}
	// credential.prove живёт там же, где SCRAM-lifecycle: доказать пароль
	// можно только SASL/SCRAM-соединением (см. ProveCredential).
	lifecycle := []adapter.Capability{
		adapter.CapAccountCreate, adapter.CapAccountDelete,
		adapter.CapCredentialRotate, adapter.CapCredentialProve,
	}
	authorizerOff := map[string]any{topologyACLAuthorizerKey: aclAuthorizerDisabledValue}

	tests := []struct {
		name     string
		conn     adapter.Connection
		topology map[string]any
		want     []adapter.Capability
	}{
		{
			name: "scram connection keeps the whole manifest",
			conn: connWith("disabled", map[string]any{attrSASLMechanism: "scram-sha-512"}),
			want: slices.Concat(inventory, aclOps, lifecycle),
		},
		{
			name: "connection without an explicit mechanism defaults to scram",
			conn: connWith("disabled", nil),
			want: slices.Concat(inventory, aclOps, lifecycle),
		},
		{
			name: "plain connection loses the scram lifecycle",
			conn: connWith("disabled", map[string]any{attrSASLMechanism: "plain"}),
			want: slices.Concat(inventory, aclOps),
		},
		{
			name: "mtls connection loses the scram lifecycle",
			conn: connWith("verify-full", map[string]any{attrSASLMechanism: "none"}),
			want: slices.Concat(inventory, aclOps),
		},
		{
			name: "incoherent auth configuration is treated as non-scram",
			conn: connWith("disabled", map[string]any{attrSecurityProtocol: "sasl_ssl"}),
			want: slices.Concat(inventory, aclOps),
		},
		{
			name:     "disabled acl authorizer removes the acl operations",
			conn:     connWith("disabled", map[string]any{attrSASLMechanism: "scram-sha-256"}),
			topology: authorizerOff,
			want:     slices.Concat(inventory, lifecycle),
		},
		{
			name:     "plain connection without an authorizer keeps inventory only",
			conn:     connWith("disabled", map[string]any{attrSASLMechanism: "plain"}),
			topology: authorizerOff,
			want:     inventory,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ad.CapabilitiesFor(tc.conn, tc.topology)
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("CapabilitiesFor = %v, want %v", got, want)
			}
		})
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		in      string
		kind    string
		topic   string
		wantErr bool
	}{
		{in: "topic-produce:orders", kind: bundleProduce, topic: "orders"},
		{in: "topic-consume:orders", kind: bundleConsume, topic: "orders"},
		{in: "cluster-admin", kind: bundleClusterAdmin, topic: ""},
		{in: "topic-produce:", wantErr: true},
		{in: "topic-consume:", wantErr: true},
		{in: "acl:topic:literal:orders:alter:allow", wantErr: true},
		{in: "topic:orders", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		kind, topic, err := parsePermission(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePermission(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePermission(%q): %v", tt.in, err)
			continue
		}
		if kind != tt.kind || topic != tt.topic {
			t.Errorf("parsePermission(%q) = (%q, %q), want (%q, %q)", tt.in, kind, topic, tt.kind, tt.topic)
		}
	}
}

func TestBundleEntries(t *testing.T) {
	produce := bundleEntries(bundleProduce, "svc", "orders")
	if len(produce) != 2 {
		t.Fatalf("produce bundle size = %d, want 2", len(produce))
	}
	wantProduce := []aclEntry{
		allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpWrite),
		allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpDescribe),
	}
	if !slices.Equal(produce, wantProduce) {
		t.Errorf("produce bundle = %v, want %v", produce, wantProduce)
	}

	consume := bundleEntries(bundleConsume, "svc", "orders")
	wantConsume := []aclEntry{
		allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpRead),
		allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpDescribe),
		allowLiteral("svc", kmsg.ACLResourceTypeGroup, "*", kadm.OpRead),
	}
	if !slices.Equal(consume, wantConsume) {
		t.Errorf("consume bundle = %v, want %v", consume, wantConsume)
	}

	admin := bundleEntries(bundleClusterAdmin, "svc", "")
	if len(admin) != 1 || admin[0].resourceType != kmsg.ACLResourceTypeCluster ||
		admin[0].name != clusterResourceName || admin[0].op != kadm.OpAll {
		t.Errorf("cluster-admin bundle = %v, want single ALL on cluster", admin)
	}

	for _, e := range slices.Concat(produce, consume, admin) {
		if e.perm != kmsg.ACLPermissionTypeAllow || e.host != "*" ||
			e.pattern != kadm.ACLPatternLiteral || e.principal != "User:svc" {
			t.Errorf("bundle entry %v must be allow/literal/host * for User:svc", e)
		}
	}
}

func TestMatchBundlesBothDirections(t *testing.T) {
	topics := map[string]bool{"orders": true, "billing": true}

	t.Run("produce and consume share topic DESCRIBE", func(t *testing.T) {
		entries := slices.Concat(
			produceEntries("svc", "orders"),
			consumeEntries("svc", "orders"),
		)
		// DESCRIBE присутствует дважды в concat; реальный describe вернул бы
		// уникальные записи — дедуплицируем как describeACLs.
		entries = dedupe(entries)
		bundles, leftover := matchBundles("svc", entries, topics)
		ids := bundleIDs(bundles)
		if !slices.Equal(ids, []string{"topic-consume:orders", "topic-produce:orders"}) {
			t.Errorf("bundles = %v, want consume+produce on orders", ids)
		}
		if len(leftover) != 0 {
			t.Errorf("leftover = %v, want empty", leftover)
		}
	})

	t.Run("group read shared across consume bundles", func(t *testing.T) {
		entries := dedupe(slices.Concat(
			consumeEntries("svc", "orders"),
			consumeEntries("svc", "billing"),
		))
		bundles, leftover := matchBundles("svc", entries, topics)
		ids := bundleIDs(bundles)
		if !slices.Equal(ids, []string{"topic-consume:billing", "topic-consume:orders"}) {
			t.Errorf("bundles = %v, want consume on billing+orders", ids)
		}
		if len(leftover) != 0 {
			t.Errorf("leftover = %v, want empty", leftover)
		}
	})

	t.Run("cluster admin", func(t *testing.T) {
		bundles, leftover := matchBundles("svc", clusterAdminEntries("svc"), topics)
		if len(bundles) != 1 || bundles[0].permissionID != clusterAdminPermission {
			t.Errorf("bundles = %v, want cluster-admin", bundles)
		}
		if bundles[0].scopeID != "" {
			t.Errorf("cluster-admin scope = %q, want cluster-wide (empty)", bundles[0].scopeID)
		}
		if len(leftover) != 0 {
			t.Errorf("leftover = %v, want empty", leftover)
		}
	})

	t.Run("incomplete bundle stays unmanaged", func(t *testing.T) {
		// WRITE без DESCRIBE — не bundle.
		entries := []aclEntry{allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpWrite)}
		bundles, leftover := matchBundles("svc", entries, topics)
		if len(bundles) != 0 {
			t.Errorf("bundles = %v, want empty", bundles)
		}
		if len(leftover) != 1 {
			t.Errorf("leftover = %v, want the lone WRITE entry", leftover)
		}
	})

	t.Run("unknown topic stays unmanaged", func(t *testing.T) {
		entries := produceEntries("svc", "ghost")
		bundles, leftover := matchBundles("svc", entries, topics)
		if len(bundles) != 0 {
			t.Errorf("bundles = %v, want empty for unknown topic", bundles)
		}
		if len(leftover) != 2 {
			t.Errorf("leftover = %v, want both entries", leftover)
		}
	})

	t.Run("host-restricted entries stay unmanaged", func(t *testing.T) {
		entries := produceEntries("svc", "orders")
		for i := range entries {
			entries[i].host = "10.0.0.1"
		}
		bundles, leftover := matchBundles("svc", entries, topics)
		if len(bundles) != 0 || len(leftover) != 2 {
			t.Errorf("bundles = %v leftover = %v, want no bundles and both entries unmanaged", bundles, leftover)
		}
	})

	t.Run("custom operation stays unmanaged", func(t *testing.T) {
		entries := slices.Concat(produceEntries("svc", "orders"), []aclEntry{
			allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpAlter),
		})
		bundles, leftover := matchBundles("svc", entries, topics)
		if ids := bundleIDs(bundles); !slices.Equal(ids, []string{"topic-produce:orders"}) {
			t.Errorf("bundles = %v, want produce on orders", ids)
		}
		if len(leftover) != 1 || leftover[0].op != kadm.OpAlter {
			t.Errorf("leftover = %v, want the ALTER entry", leftover)
		}
	})
}

// TestRevokeEntriesSharedACLs проверяет деградацию до реконструкции из движка:
// ядро desired-состояние не передало (AccountPermissions == nil).
func TestRevokeEntriesSharedACLs(t *testing.T) {
	full := dedupe(slices.Concat(
		produceEntries("svc", "orders"),
		consumeEntries("svc", "orders"),
		consumeEntries("svc", "billing"),
	))

	t.Run("revoke produce keeps shared describe", func(t *testing.T) {
		out := revokeEntries(bundleProduce, "svc", "orders", full, nil, false)
		want := []aclEntry{allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpWrite)}
		if !slices.Equal(out, want) {
			t.Errorf("revoke produce = %v, want only WRITE (DESCRIBE shared with consume)", out)
		}
	})

	t.Run("revoke consume keeps shared describe and group read", func(t *testing.T) {
		out := revokeEntries(bundleConsume, "svc", "orders", full, nil, false)
		want := []aclEntry{allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpRead)}
		if !slices.Equal(out, want) {
			t.Errorf("revoke consume = %v, want only READ (DESCRIBE shared with produce, group READ with billing)", out)
		}
	})

	t.Run("revoke last consume removes group read", func(t *testing.T) {
		only := consumeEntries("svc", "orders")
		out := revokeEntries(bundleConsume, "svc", "orders", only, nil, false)
		want := []aclEntry{
			allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpRead),
			allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpDescribe),
			allowLiteral("svc", kmsg.ACLResourceTypeGroup, "*", kadm.OpRead),
		}
		if !slices.Equal(out, want) {
			t.Errorf("revoke last consume = %v, want full bundle removal", out)
		}
	})

	t.Run("revoke absent bundle deletes nothing", func(t *testing.T) {
		if out := revokeEntries(bundleProduce, "svc", "billing", full, nil, false); len(out) != 0 {
			t.Errorf("revoke absent produce = %v, want empty", out)
		}
	})
}

// revokeChange собирает revoke-изменение с переданным desired-набором прав
// аккаунта (nil = ядро набор не передало).
func revokeChange(permission string, accountPermissions []string) adapter.DesiredChange {
	return adapter.DesiredChange{
		Kind:               adapter.ChangeRevoke,
		Account:            adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Permission:         permission,
		AccountPermissions: accountPermissions,
	}
}

// TestRevokeEntriesFromDesiredState проверяет главное свойство фикса: что
// именно сохранить при отзыве, решает desired-состояние ядра, а не ответ
// брокера. Неполный ответ DescribeAcls не должен приводить к удалению записи,
// которая нужна другому желаемому праву аккаунта.
func TestRevokeEntriesFromDesiredState(t *testing.T) {
	full := dedupe(slices.Concat(
		produceEntries("svc", "orders"),
		consumeEntries("svc", "orders"),
	))
	write := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpWrite)
	describe := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpDescribe)
	read := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpRead)
	groupRead := allowLiteral("svc", kmsg.ACLResourceTypeGroup, wildcardName, kadm.OpRead)

	t.Run("shared describe survives an incomplete broker answer", func(t *testing.T) {
		// Брокер «потерял» READ в ответе, хотя consume:orders остаётся
		// желаемым правом аккаунта. По состоянию движка DESCRIBE был бы
		// удалён вместе с produce — и consume молча сломался бы.
		incomplete := []aclEntry{write, describe}
		change := revokeChange("topic-produce:orders", []string{"topic-consume:orders"})
		desired, hasDesired, err := desiredEntries(change, "svc")
		if err != nil || !hasDesired {
			t.Fatalf("desiredEntries = %v, %v, %v", desired, hasDesired, err)
		}
		out := revokeEntries(bundleProduce, "svc", "orders", incomplete, desired, hasDesired)
		if !slices.Equal(out, []aclEntry{write}) {
			t.Errorf("revoke produce = %v, want only WRITE: DESCRIBE is required by the desired consume bundle", out)
		}
		// Та же ситуация без desired-состояния — прежняя потеря DESCRIBE.
		legacy := revokeEntries(bundleProduce, "svc", "orders", incomplete, nil, false)
		if !slices.Equal(legacy, []aclEntry{write, describe}) {
			t.Errorf("legacy revoke = %v, want WRITE+DESCRIBE (reconstruction from the engine)", legacy)
		}
	})

	t.Run("desired state without the bundle removes shared describe", func(t *testing.T) {
		change := revokeChange("topic-produce:orders", []string{})
		desired, hasDesired, err := desiredEntries(change, "svc")
		if err != nil || !hasDesired {
			t.Fatalf("desiredEntries = %v, %v, %v", desired, hasDesired, err)
		}
		out := revokeEntries(bundleProduce, "svc", "orders", full, desired, hasDesired)
		if !slices.Equal(out, []aclEntry{write, describe}) {
			t.Errorf("revoke produce = %v, want WRITE+DESCRIBE: no desired permission needs DESCRIBE", out)
		}
	})

	t.Run("group read is decided by the engine state across scopes", func(t *testing.T) {
		// Ядро передаёт desired-набор только того же scope, поэтому
		// consume другого topic виден лишь в состоянии движка.
		current := dedupe(slices.Concat(
			consumeEntries("svc", "orders"),
			consumeEntries("svc", "billing"),
		))
		change := revokeChange("topic-consume:orders", []string{})
		desired, hasDesired, _ := desiredEntries(change, "svc")
		out := revokeEntries(bundleConsume, "svc", "orders", current, desired, hasDesired)
		if slices.Contains(out, groupRead) {
			t.Errorf("revoke consume = %v, must keep group read while another topic is consumed", out)
		}
		if !slices.Equal(out, []aclEntry{read, describe}) {
			t.Errorf("revoke consume = %v, want READ+DESCRIBE", out)
		}
	})

	t.Run("inconsistent desired state is rejected", func(t *testing.T) {
		change := revokeChange("topic-produce:orders", []string{"topic-produce:orders"})
		if _, _, err := desiredEntries(change, "svc"); err == nil {
			t.Error("desired state still containing the revoked permission must be rejected")
		}
		grant := revokeChange("topic-produce:orders", []string{"topic-consume:orders"})
		grant.Kind = adapter.ChangeGrant
		if _, _, err := desiredEntries(grant, "svc"); err == nil {
			t.Error("desired state without the granted permission must be rejected")
		}
	})

	t.Run("unassignable observed permissions are ignored", func(t *testing.T) {
		change := revokeChange("topic-produce:orders",
			[]string{"acl:topic:literal:orders:alter:allow", "topic-consume:orders"})
		desired, hasDesired, err := desiredEntries(change, "svc")
		if err != nil || !hasDesired {
			t.Fatalf("desiredEntries = %v, %v, %v", desired, hasDesired, err)
		}
		if !slices.Equal(desired, consumeEntries("svc", "orders")) {
			t.Errorf("desired = %v, want only the consume bundle entries", desired)
		}
	})
}

// TestGroupReadLost проверяет инвариант, которым Verify ловит cross-scope
// потерю READ на group "*".
func TestGroupReadLost(t *testing.T) {
	if groupReadLost(produceEntries("svc", "orders"), "svc") {
		t.Error("produce-only principal has no topic read and must not be reported broken")
	}
	if groupReadLost(consumeEntries("svc", "orders"), "svc") {
		t.Error("intact consume bundle must not be reported broken")
	}
	broken := slices.DeleteFunc(consumeEntries("svc", "orders"), func(e aclEntry) bool {
		return e.resourceType == kmsg.ACLResourceTypeGroup
	})
	if !groupReadLost(broken, "svc") {
		t.Error("topic read without group read must be reported broken")
	}
}

func TestDangerousEntry(t *testing.T) {
	cluster := func(op kadm.ACLOperation) aclEntry {
		return allowLiteral("svc", kmsg.ACLResourceTypeCluster, clusterResourceName, op)
	}
	for _, op := range []kadm.ACLOperation{kadm.OpAll, kadm.OpAlter, kadm.OpClusterAction, kadm.OpIdempotentWrite} {
		if !dangerousEntry(cluster(op)) {
			t.Errorf("cluster %s must be dangerous", op)
		}
	}
	for _, op := range []kadm.ACLOperation{kadm.OpDescribe, kadm.OpDescribeConfigs, kadm.OpCreate} {
		if dangerousEntry(cluster(op)) {
			t.Errorf("cluster %s must not be dangerous", op)
		}
	}

	if !dangerousEntry(allowLiteral("svc", kmsg.ACLResourceTypeTopic, "*", kadm.OpAll)) {
		t.Error("ALL on wildcard topic must be dangerous")
	}
	if dangerousEntry(allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpAll)) {
		t.Error("ALL on a concrete topic must not be dangerous")
	}
	if dangerousEntry(allowLiteral("svc", kmsg.ACLResourceTypeTopic, "*", kadm.OpWrite)) {
		t.Error("WRITE on wildcard topic must not be dangerous")
	}
	if dangerousEntry(allowLiteral("svc", kmsg.ACLResourceTypeGroup, "*", kadm.OpAll)) {
		t.Error("ALL on wildcard group must not be dangerous")
	}

	deny := allowLiteral("svc", kmsg.ACLResourceTypeCluster, clusterResourceName, kadm.OpAll)
	deny.perm = kmsg.ACLPermissionTypeDeny
	if dangerousEntry(deny) {
		t.Error("DENY entries must not be dangerous")
	}
}

func TestDisableMarker(t *testing.T) {
	marker := markerEntries("svc")
	if len(marker) != 3 {
		t.Fatalf("marker size = %d, want 3", len(marker))
	}
	for _, e := range marker {
		if e.perm != kmsg.ACLPermissionTypeDeny || e.op != kadm.OpAll || e.host != "*" {
			t.Errorf("marker entry %v must be DENY ALL host *", e)
		}
	}

	allow := produceEntries("svc", "orders")
	if isDisabled(allow, "svc") {
		t.Error("allow-only entries must not be disabled")
	}
	if isDisabled(marker[:2], "svc") {
		t.Error("partial marker must not be disabled")
	}
	all := slices.Concat(allow, marker)
	if !isDisabled(all, "svc") {
		t.Error("full marker must be disabled")
	}
	rest := withoutMarker(all, "svc")
	if !slices.Equal(rest, allow) {
		t.Errorf("withoutMarker = %v, want allow entries %v", rest, allow)
	}
	if isDisabled(markerEntries("other"), "svc") {
		t.Error("marker of another principal must not disable svc")
	}
}

func TestTopologyFromMetadata(t *testing.T) {
	broker := func(id int32, host string) kadm.BrokerDetail {
		return kadm.BrokerDetail{NodeID: id, Host: host, Port: 9092}
	}

	t.Run("standalone", func(t *testing.T) {
		topo := topologyFromMetadata(kadm.Metadata{
			Cluster:    "redpanda.a1",
			Controller: 0,
			Brokers:    kadm.BrokerDetails{broker(0, "rp1")},
		})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone", topo["topology"])
		}
		if topo["broker_count"] != 1 {
			t.Errorf("broker_count = %v, want 1", topo["broker_count"])
		}
		if topo["controller"] != 0 {
			t.Errorf("controller = %v, want 0", topo["controller"])
		}
		if topo["cluster_id"] != "redpanda.a1" {
			t.Errorf("cluster_id = %v, want redpanda.a1", topo["cluster_id"])
		}
	})

	t.Run("cluster", func(t *testing.T) {
		topo := topologyFromMetadata(kadm.Metadata{
			Controller: 2,
			Brokers:    kadm.BrokerDetails{broker(2, "b"), broker(1, "a"), broker(3, "c")},
		})
		if topo["topology"] != "cluster" {
			t.Errorf("topology = %v, want cluster", topo["topology"])
		}
		if topo["broker_count"] != 3 {
			t.Errorf("broker_count = %v, want 3", topo["broker_count"])
		}
		brokers, ok := topo["brokers"].([]string)
		if !ok || !slices.Equal(brokers, []string{"1@a:9092", "2@b:9092", "3@c:9092"}) {
			t.Errorf("brokers = %v, want sorted [1@a:9092 2@b:9092 3@c:9092]", topo["brokers"])
		}
	})

	t.Run("empty", func(t *testing.T) {
		topo := topologyFromMetadata(kadm.Metadata{Controller: -1})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone for empty brokers", topo["topology"])
		}
	})
}

func TestTopicPermissionsAndClusterAdmin(t *testing.T) {
	perms := topicPermissions("orders", true)
	if len(perms) != 2 {
		t.Fatalf("permission count = %d, want 2", len(perms))
	}
	byID := map[string]adapter.ObservedPermission{}
	for _, p := range perms {
		byID[p.ExternalID] = p
		if !p.Assignable {
			t.Errorf("permission %q must be assignable", p.ExternalID)
		}
		if p.Dangerous {
			t.Errorf("permission %q must not be dangerous", p.ExternalID)
		}
		if p.ScopeExternalID != "topic:orders" {
			t.Errorf("permission %q scope = %q, want topic:orders", p.ExternalID, p.ScopeExternalID)
		}
	}
	if _, ok := byID["topic-produce:orders"]; !ok {
		t.Error("topic-produce:orders must exist")
	}
	if _, ok := byID["topic-consume:orders"]; !ok {
		t.Error("topic-consume:orders must exist")
	}

	admin := clusterAdminPermissionDef(true)
	if admin.ExternalID != clusterAdminPermission || !admin.Dangerous || !admin.Assignable {
		t.Errorf("cluster-admin = %+v, want assignable dangerous", admin)
	}
	if admin.ScopeExternalID != "" {
		t.Errorf("cluster-admin scope = %q, want cluster-wide (empty)", admin.ScopeExternalID)
	}
}

func TestObservedACLPermission(t *testing.T) {
	e := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpAlter)
	id := aclPermissionID(e)
	if id != "acl:topic:literal:orders:alter:allow" {
		t.Errorf("aclPermissionID = %q, want acl:topic:literal:orders:alter:allow", id)
	}
	p := observedACLPermission(e, "topic:orders")
	if p.Assignable {
		t.Error("observed acl permission must not be assignable")
	}
	if p.Dangerous {
		t.Error("topic ALTER must not be dangerous")
	}
	if p.ScopeExternalID != "topic:orders" {
		t.Errorf("scope = %q, want topic:orders", p.ScopeExternalID)
	}

	cluster := allowLiteral("svc", kmsg.ACLResourceTypeCluster, clusterResourceName, kadm.OpAlter)
	cp := observedACLPermission(cluster, "")
	if !cp.Dangerous {
		t.Error("cluster ALTER (ACL administration) must be dangerous")
	}
}

func TestObservedACLBindingsAggregatesHosts(t *testing.T) {
	e1 := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpAlter)
	e1.host = "10.0.0.2"
	e2 := e1
	e2.host = "10.0.0.1"
	permByID := map[string]adapter.ObservedPermission{}
	bindings := observedACLBindings("svc", []aclEntry{e1, e2}, map[string]bool{"orders": true}, permByID)
	if len(bindings) != 1 {
		t.Fatalf("bindings = %v, want single aggregated binding", bindings)
	}
	hosts, _ := bindings[0].Attributes["hosts"].([]string)
	if !slices.Equal(hosts, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("hosts = %v, want sorted [10.0.0.1 10.0.0.2]", hosts)
	}
	if bindings[0].ScopeExternalID != "topic:orders" {
		t.Errorf("scope = %q, want topic:orders", bindings[0].ScopeExternalID)
	}
	if _, ok := permByID["acl:topic:literal:orders:alter:allow"]; !ok {
		t.Error("observed permission must be registered in permByID")
	}
}

func TestIsInternalTopic(t *testing.T) {
	for _, name := range []string{"__consumer_offsets", "__transaction_state", "__redpanda.audit_log", "_redpanda.controller", "_schemas"} {
		if !isInternalTopic(name, false) {
			t.Errorf("topic %q must be internal", name)
		}
	}
	if !isInternalTopic("anything", true) {
		t.Error("metadata internal flag must win")
	}
	for _, name := range []string{"orders", "_private_but_user", "app.events"} {
		if isInternalTopic(name, false) {
			t.Errorf("topic %q must not be internal", name)
		}
	}
}

func TestGroupByPrincipal(t *testing.T) {
	usr := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpWrite)
	wildcard := usr
	wildcard.principal = "User:*"
	group := usr
	group.principal = "Group:ops"
	empty := usr
	empty.principal = "User:"

	byPrincipal := groupByPrincipal([]aclEntry{usr, wildcard, group, empty})
	if len(byPrincipal) != 1 {
		t.Fatalf("principals = %v, want only svc", byPrincipal)
	}
	if len(byPrincipal["svc"]) != 1 {
		t.Errorf("svc entries = %v, want 1", byPrincipal["svc"])
	}
}

func TestExternalIDs(t *testing.T) {
	if got := topicExternalID("orders"); got != "topic:orders" {
		t.Errorf("topicExternalID = %q, want topic:orders", got)
	}
	if got := producePermissionID("orders"); got != "topic-produce:orders" {
		t.Errorf("producePermissionID = %q, want topic-produce:orders", got)
	}
	if got := consumePermissionID("orders"); got != "topic-consume:orders" {
		t.Errorf("consumePermissionID = %q, want topic-consume:orders", got)
	}
	if got := userPrincipal("svc"); got != "User:svc" {
		t.Errorf("userPrincipal = %q, want User:svc", got)
	}
}

func TestFingerprintDeterminism(t *testing.T) {
	attrs := map[string]any{"partitions": 3, "replication_factor": 2}
	same := map[string]any{"replication_factor": 2, "partitions": 3}
	a := fingerprint("topic", "topic:orders", attrs)
	b := fingerprint("topic", "topic:orders", same)
	if a != b {
		t.Errorf("fingerprints for identical content differ: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}
	if fingerprint("topic", "topic:other", attrs) == a {
		t.Error("fingerprint must change when external id changes")
	}
	if fingerprint("topic", "topic:orders", map[string]any{"partitions": 4}) == a {
		t.Error("fingerprint must change when attributes change")
	}
}

func TestPlanAccessRedactsSecretAndParses(t *testing.T) {
	ad := New()
	const marker = "s3cr3t-marker"
	change := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Permission: "topic-produce:orders",
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	}
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepGrantPermission {
		t.Fatalf("unexpected plan steps: %+v", plan.Steps)
	}
	step := plan.Steps[0]
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
	for k, v := range step.Attributes {
		if strings.Contains(fmt.Sprint(v), marker) {
			t.Errorf("plan attribute %q leaks secret", k)
		}
	}
	if step.Attributes["user"] != "svc" || step.Attributes["topic"] != "orders" {
		t.Errorf("plan attributes = %v, want user=svc topic=orders", step.Attributes)
	}

	revoke := change
	revoke.Kind = adapter.ChangeRevoke
	rplan, err := ad.Plan(t.Context(), revoke)
	if err != nil {
		t.Fatalf("Plan(revoke): %v", err)
	}
	if rplan.Steps[0].Kind != stepRevokePermission {
		t.Errorf("revoke step kind = %q, want %q", rplan.Steps[0].Kind, stepRevokePermission)
	}

	admin := change
	admin.Permission = "cluster-admin"
	aplan, err := ad.Plan(t.Context(), admin)
	if err != nil {
		t.Fatalf("Plan(cluster-admin): %v", err)
	}
	if aplan.Steps[0].Attributes["cluster"] != clusterResourceName {
		t.Errorf("cluster-admin attributes = %v, want cluster=%s", aplan.Steps[0].Attributes, clusterResourceName)
	}
}

func TestPlanAccountCreateRequiresPassword(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeAccountCreate,
		Account: adapter.Account{Kind: "login", EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("account.create without password credential must fail")
	}

	// Форма плана проверяется без кластера: сам Plan обращается к Kafka, чтобы
	// отказать в создании поверх существующего SCRAM credential.
	const marker = "s3cr3t-marker"
	plan := accountCreatePlan(adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	})
	step := plan.Steps[0]
	if step.Kind != stepCreateUser || step.Attributes["with_password"] != true {
		t.Errorf("unexpected create step: %+v", step)
	}
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
}

func TestPlanDisableEnable(t *testing.T) {
	ad := New()
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}

	dis, err := ad.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Account: acct})
	if err != nil {
		t.Fatalf("Plan(disable): %v", err)
	}
	if dis.Steps[0].Kind != stepDisableUser {
		t.Errorf("disable step kind = %q, want %q", dis.Steps[0].Kind, stepDisableUser)
	}
	if dis.Steps[0].Attributes["marker"] != "deny-all" {
		t.Errorf("disable marker attribute = %v, want deny-all", dis.Steps[0].Attributes["marker"])
	}

	en, err := ad.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Account: acct})
	if err != nil {
		t.Fatalf("Plan(enable): %v", err)
	}
	if en.Steps[0].Kind != stepEnableUser {
		t.Errorf("enable step kind = %q, want %q", en.Steps[0].Kind, stepEnableUser)
	}
}

// TestPlanCapabilityDowngradeNonScram проверяет, что SCRAM-lifecycle операции
// (account.create/account.delete/credential.rotate) недоступны на не-SCRAM
// подключении и отклоняются как adapter.ErrUnsupportedChange, а inventory/ACL
// операции (grant/disable/enable) остаются доступны.
func TestPlanCapabilityDowngradeNonScram(t *testing.T) {
	ad := New()
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}
	plainConn := connWith("disabled", map[string]any{attrSASLMechanism: "plain"})

	// account.create / account.delete отклоняются как unsupported.
	for _, kind := range []adapter.ChangeKind{adapter.ChangeAccountCreate, adapter.ChangeAccountDelete} {
		change := adapter.DesiredChange{
			Kind:       kind,
			Connection: plainConn,
			Account:    acct,
			Credential: &adapter.Credential{Kind: "password", Secret: []byte("pw")},
		}
		_, err := ad.Plan(t.Context(), change)
		if err == nil {
			t.Errorf("Plan(%s) on plain connection must fail", kind)
			continue
		}
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(%s) error = %v, want adapter.ErrUnsupportedChange", kind, err)
		}
	}

	// credential.rotate отклоняется как unsupported.
	err := ad.RotateCredential(t.Context(), plainConn, acct, adapter.Credential{Kind: "password", Secret: []byte("pw")})
	if err == nil {
		t.Error("RotateCredential on plain connection must fail")
	} else if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("RotateCredential error = %v, want adapter.ErrUnsupportedChange", err)
	}

	// grant / disable / enable остаются доступны (ACL-операции, не SCRAM).
	for _, change := range []adapter.DesiredChange{
		{Kind: adapter.ChangeGrant, Connection: plainConn, Account: acct, Permission: "topic-produce:orders"},
		{Kind: adapter.ChangeAccountDisable, Connection: plainConn, Account: acct},
		{Kind: adapter.ChangeAccountEnable, Connection: plainConn, Account: acct},
	} {
		if _, err := ad.Plan(t.Context(), change); err != nil {
			t.Errorf("Plan(%s) on plain connection must succeed, got %v", change.Kind, err)
		}
	}

	// На SCRAM-подключении (по умолчанию) account.create доступна: гейт
	// capability её пропускает. Дальше Plan идёт в кластер (проверить, что
	// пользователя ещё нет), поэтому без брокера он отказывает — но уже не как
	// unsupported.
	scramConn := connWith("disabled", map[string]any{attrSASLMechanism: "scram-sha-256"})
	_, err = ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Connection: scramConn,
		Account:    acct,
		Credential: &adapter.Credential{Kind: "password", Secret: []byte("pw")},
	})
	if errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("Plan(account.create) on scram connection must not be unsupported, got %v", err)
	}
}

func TestPlanUnsupportedChange(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeResourceCreate,
		Account: adapter.Account{EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("Plan(resource.create): expected unsupported change error")
	}

	_, err = ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{EngineIdentity: "svc"},
		Permission: "acl:topic:literal:orders:alter:allow",
	})
	if err == nil {
		t.Error("Plan(grant) with an observed acl permission must fail")
	}
}

func TestGenerateCredential(t *testing.T) {
	ad := New()
	cred, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if cred.Kind != "password" {
		t.Errorf("kind = %q, want password", cred.Kind)
	}
	if len(cred.Secret) != adapterutil.DefaultPasswordLength {
		t.Errorf("default length = %d, want %d", len(cred.Secret), adapterutil.DefaultPasswordLength)
	}
	for _, b := range cred.Secret {
		if !strings.ContainsRune(adapterutil.PasswordAlphabet, rune(b)) {
			t.Fatalf("password contains char outside alphabet: %q", string(b))
		}
	}

	custom, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{Length: 12})
	if err != nil {
		t.Fatalf("GenerateCredential(12): %v", err)
	}
	if len(custom.Secret) != 12 {
		t.Errorf("custom length = %d, want 12", len(custom.Secret))
	}

	other, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if string(other.Secret) == string(cred.Secret) {
		t.Error("two generated passwords must differ")
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "kafka.example.com:9093", host: "kafka.example.com", port: 9093},
		{endpoint: "kafka.example.com", host: "kafka.example.com", port: defaultPort},
		{endpoint: "[::1]:9092", host: "::1", port: 9092},
		{endpoint: "kafka.example.com:notaport", wantErr: true},
		{endpoint: "kafka.example.com:0", wantErr: true},
		{endpoint: "", wantErr: true},
	}
	for _, tt := range tests {
		host, port, err := adapterutil.SplitEndpoint(tt.endpoint, defaultPort)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitEndpoint(%q): expected error", tt.endpoint)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitEndpoint(%q): %v", tt.endpoint, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("splitEndpoint(%q) = (%q, %d), want (%q, %d)", tt.endpoint, host, port, tt.host, tt.port)
		}
	}
}

func TestNewClientNoSecretLeak(t *testing.T) {
	const password = "s3cr3t-admin-password"
	// Секрет не должен утекать ни при каком SASL-механизме (plain хранит пароль
	// в открытом виде внутри механизма, поэтому проверяем и его).
	for _, mech := range []string{"plain", "scram-sha-256", "scram-sha-512"} {
		t.Run(mech, func(t *testing.T) {
			cfg := adapter.Connection{
				Engine:     Engine,
				Endpoints:  []string{"kafka.example.com:9092"},
				TLS:        adapter.TLSConfig{Mode: "disabled"},
				Attributes: map[string]any{attrSASLMechanism: mech},
				AdminCredential: adapter.Credential{
					Kind:     "password",
					Username: "admin",
					Secret:   []byte(password),
				},
			}
			c, err := newClient(cfg)
			if err != nil {
				t.Fatalf("newClient: %v", err)
			}
			defer c.close()
			if c.username != "admin" {
				t.Errorf("username = %q, want admin", c.username)
			}

			// Секрет не должен появляться ни в одном текстовом представлении
			// клиентской обёртки.
			for _, rendered := range []string{
				fmt.Sprintf("%v", c),
				fmt.Sprintf("%+v", c),
				fmt.Sprintf("%#v", c),
				fmt.Sprintf("%s", c.secret),
				fmt.Sprintf("%v", c.secret),
			} {
				if strings.Contains(rendered, password) {
					t.Errorf("rendered client leaks secret: %q", rendered)
				}
			}
			raw, err := json.Marshal(c.secret)
			if err != nil {
				t.Fatalf("marshal secret: %v", err)
			}
			if strings.Contains(string(raw), password) {
				t.Errorf("marshaled secret leaks value: %s", raw)
			}
		})
	}
}

// TestNewClientNoneMechanismSkipsCredential проверяет, что при mechanism=none
// (mTLS) логин и пароль не обязательны: SASL не строится.
func TestNewClientNoneMechanismSkipsCredential(t *testing.T) {
	cfg := adapter.Connection{
		Engine:     Engine,
		Endpoints:  []string{"kafka.example.com:9092"},
		TLS:        adapter.TLSConfig{Mode: "verify-full"},
		Attributes: map[string]any{attrSASLMechanism: "none"},
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient with mechanism=none and no credential: %v", err)
	}
	defer c.close()
	if c.auth.mechanism != mechNone || c.auth.protocol != protoSSL {
		t.Errorf("auth = %+v, want mechanism none over ssl", c.auth)
	}
}

// TestNewClientCoherenceError проверяет, что несогласованная auth-конфигурация
// (sasl_ssl без TLS) отклоняется на этапе newClient.
func TestNewClientCoherenceError(t *testing.T) {
	cfg := adapter.Connection{
		Engine:     Engine,
		Endpoints:  []string{"kafka.example.com:9092"},
		TLS:        adapter.TLSConfig{Mode: "disabled"},
		Attributes: map[string]any{attrSASLMechanism: "scram-sha-256", attrSecurityProtocol: "sasl_ssl"},
		AdminCredential: adapter.Credential{
			Kind: "password", Username: "admin", Secret: []byte("pw"),
		},
	}
	if _, err := newClient(cfg); err == nil {
		t.Error("newClient with sasl_ssl over disabled tls must fail")
	}
}

func TestNewClientValidation(t *testing.T) {
	base := adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{"kafka.example.com:9092"},
		AdminCredential: adapter.Credential{
			Kind: "password", Username: "admin", Secret: []byte("pw"),
		},
	}

	noEndpoints := base
	noEndpoints.Endpoints = nil
	if _, err := newClient(noEndpoints); err == nil {
		t.Error("newClient without endpoints must fail")
	}

	noUser := base
	noUser.AdminCredential.Username = ""
	if _, err := newClient(noUser); err == nil {
		t.Error("newClient without admin username must fail")
	}

	noSecret := base
	noSecret.AdminCredential.Secret = nil
	if _, err := newClient(noSecret); err == nil {
		t.Error("newClient without admin secret must fail")
	}

	badTLS := base
	badTLS.TLS = adapter.TLSConfig{Mode: "bogus"}
	if _, err := newClient(badTLS); err == nil {
		t.Error("newClient with unsupported tls mode must fail")
	}
}

// dedupe убирает дубли записей, как это делает describeACLs.
func dedupe(entries []aclEntry) []aclEntry {
	seen := map[aclEntry]bool{}
	out := make([]aclEntry, 0, len(entries))
	for _, e := range entries {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

// bundleIDs возвращает отсортированные permission ids bundles.
func bundleIDs(bundles []bundleBinding) []string {
	out := make([]string, 0, len(bundles))
	for _, b := range bundles {
		out = append(out, b.permissionID)
	}
	slices.Sort(out)
	return out
}
