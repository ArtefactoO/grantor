//go:build integration

package rabbitmq_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
)

func TestMonitoringVisibilityLifecycleRejectsResourceActions(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, adminUser, adminPass)
	admin := &mgmt{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	vhostPath := url.PathEscape(appVhost)
	userPath := url.PathEscape(fixtureUser)
	queue := "monitoring_probe_" + adaptertest.RandomHex(t, 4)
	queuePath := "/api/queues/" + vhostPath + "/" + url.PathEscape(queue)
	admin.put(ctx, t, queuePath, map[string]any{"durable": false, "auto_delete": false, "arguments": map[string]any{}})
	t.Cleanup(func() {
		admin.delete(context.Background(), queuePath)
		admin.put(context.Background(), t, "/api/permissions/"+vhostPath+"/"+userPath,
			map[string]any{"configure": ".*", "write": ".*", "read": ".*"})
	})
	conn := connectionFromURL(t, rawURL)
	change := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn,
		Account:    adapter.Account{Kind: "login", EngineIdentity: fixtureUser},
		Permission: "vhost-monitoring:" + appVhost, Scope: "vhost:" + appVhost,
	}
	ad := rabbitmq.New()
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	status, data := admin.do(ctx, t, http.MethodGet, "/api/permissions/"+vhostPath+"/"+userPath, nil)
	var tuple struct {
		Configure string `json:"configure"`
		Write     string `json:"write"`
		Read      string `json:"read"`
	}
	if status != http.StatusOK || json.Unmarshal(data, &tuple) != nil || tuple.Configure != "^$" || tuple.Write != "^$" || tuple.Read != "^$" {
		t.Fatalf("target does not hold an exact monitoring tuple: status=%d tuple=%+v", status, tuple)
	}
	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !hasBinding(snap, fixtureUser, change.Permission) || !hasBinding(snap, fixtureUser, "tag:monitoring") {
		t.Fatal("discovery must retain separate vhost visibility and monitoring tag bindings")
	}
	monitor := &mgmt{base: base, user: fixtureUser, pass: "app_svc_fixture_pwd", hc: httpClient()}
	if status, _ := monitor.do(ctx, t, http.MethodGet, queuePath, nil); status != http.StatusOK {
		t.Fatalf("monitor cannot view queue statistics: status=%d", status)
	}
	for _, tc := range []struct {
		name, method, path string
		body               any
	}{
		{"configure", http.MethodPut, queuePath, map[string]any{"durable": false, "auto_delete": false, "arguments": map[string]any{}}},
		{"publish", http.MethodPost, "/api/exchanges/" + vhostPath + "/amq.default/publish", map[string]any{
			"properties": map[string]any{}, "routing_key": queue, "payload": "probe", "payload_encoding": "string",
		}},
		{"consume", http.MethodPost, queuePath + "/get", map[string]any{"count": 1, "ackmode": "ack_requeue_true", "encoding": "auto"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, data := monitor.do(ctx, t, tc.method, tc.path, tc.body)
			denied := status == http.StatusUnauthorized || status == http.StatusForbidden
			var failure struct {
				Reason string `json:"reason"`
			}
			// RabbitMQ versions also map AMQP access_refused to an HTTP 400.
			// An unrelated malformed publish request must not satisfy this test.
			if tc.name == "publish" && status == http.StatusBadRequest && json.Unmarshal(data, &failure) == nil {
				reason := strings.ToLower(failure.Reason)
				denied = strings.Contains(reason, "access refused") || strings.Contains(reason, "access_refused")
			}
			if !denied {
				t.Fatalf("resource action was not denied by permissions: action=%s status=%d reason=%q", tc.name, status, failure.Reason)
			}
		})
	}
	change.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	if status, _ := admin.do(ctx, t, http.MethodGet, "/api/permissions/"+vhostPath+"/"+userPath, nil); status != http.StatusNotFound {
		t.Fatalf("revoke left a vhost assignment: status=%d", status)
	}
	if status := login(ctx, t, base, fixtureUser, "app_svc_fixture_pwd"); status != http.StatusOK {
		t.Fatalf("vhost revoke must preserve the independent monitoring tag and password: status=%d", status)
	}
}
