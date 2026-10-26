//go:build integration

package redis_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	adredis "github.com/ArtefactoO/grantor/internal/adapters/redis"
)

// The same test runs against disposable Redis 6.2 and 7 through REDIS_IMAGE.
// Permission proof uses actual commands, not only the adapter's ACL parser.
func TestMonitoringAccountBoundariesAndRevoke(t *testing.T) {
	addr, adminPass := target(t)
	ctx := t.Context()
	conn := connection(addr, adminPass)
	ad := adredis.New()
	adm := adminGoRedis(t, addr, "", adminPass)
	name := "gr_monitor_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name}
	t.Cleanup(func() { _ = adm.ACLDelUser(context.Background(), name).Err() })
	credential, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	defer clear(credential.Secret)
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: credential,
	})
	// Redis 6.2's allchannels default must not leak into the empty form.
	users, err := adm.ACLList(ctx).Result()
	if err != nil {
		t.Fatal("cannot inspect fixture ACL metadata")
	}
	found := false
	for _, line := range users {
		if !strings.HasPrefix(line, "user "+name+" ") {
			continue
		}
		found = true
		for _, token := range strings.Fields(line) {
			if strings.HasPrefix(token, "~") || strings.HasPrefix(token, "&") || strings.HasPrefix(token, "%") {
				t.Fatal("new monitoring account must begin without key or channel patterns")
			}
		}
	}
	if !found {
		t.Fatal("new account was not observed")
	}
	client := goredis.NewClient(&goredis.Options{
		Addr: addr, Username: name, Password: string(credential.Secret), MaxRetries: -1,
		DialTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
	})
	t.Cleanup(func() { _ = client.Close() })
	access := func(kind adapter.ChangeKind, permission string, desired []string) adapter.DesiredChange {
		return adapter.DesiredChange{Kind: kind, Connection: conn, Account: account,
			Permission: permission, AccountPermissions: desired}
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "monitoring", []string{"monitoring"}))
	assertAllowed := func(command ...any) {
		t.Helper()
		if err := client.Do(ctx, command...).Err(); err != nil {
			t.Fatalf("monitoring command %s failed: %v", fmt.Sprint(command[0]), err)
		}
	}
	assertDenied := func(command ...any) {
		t.Helper()
		if err := client.Do(ctx, command...).Err(); !goredis.HasErrorPrefix(err, "NOPERM") {
			t.Fatalf("command %s error=%v; want NOPERM", fmt.Sprint(command[0]), err)
		}
	}
	assertAllowed("PING")
	assertAllowed("INFO")
	assertAllowed("HELLO", 3)
	assertAllowed("CLIENT", "SETNAME", "grantor-monitoring-regression")
	for _, command := range [][]any{
		{"GET", probeKey}, {"SCAN", 0}, {"SET", probeKey, "monitoring-must-not-write"},
		{"DEL", probeKey}, {"PUBLISH", "grantor:it:channel", "monitoring-must-not-publish"},
		{"CONFIG", "GET", "aclfile"}, {"ACL", "LIST"}, {"CLIENT", "LIST"}, {"CLIENT", "KILL", "ID", 0},
	} {
		assertDenied(command...)
	}
	// CLIENT SETINFO is absent in 6.2; allowing its first argument must not
	// break the older ACL command syntax or grant any other CLIENT operation.
	setInfoErr := client.Do(ctx, "CLIENT", "SETINFO", "LIB-NAME", "grantor-regression").Err()
	if setInfoErr != nil && !strings.HasPrefix(setInfoErr.Error(), "ERR Unknown subcommand") {
		t.Fatalf("CLIENT SETINFO error=%v; want allowed or unsupported on an older Redis", setInfoErr)
	}
	if err := ad.ProveCredential(ctx, conn, account, *credential); err != nil {
		t.Fatalf("monitoring password proof: %v", err)
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "read", []string{"read", "monitoring"}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "write", []string{"read", "write", "monitoring"}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeRevoke, "monitoring", []string{"read", "write"}))
	assertDenied("INFO")
	if err := client.Set(ctx, probeKey, "explicit-read-write", time.Minute).Err(); err != nil {
		t.Fatalf("explicit write must survive monitoring revoke: %v", err)
	}
	t.Cleanup(func() { _ = adm.Del(context.Background(), probeKey).Err() })
	if value, err := client.Get(ctx, probeKey).Result(); err != nil || value != "explicit-read-write" {
		t.Fatalf("explicit read must survive monitoring revoke: error=%v", err)
	}
	// A fresh authentication under the original password still succeeds.
	if err := ad.ProveCredential(ctx, conn, account, *credential); err != nil {
		t.Fatalf("password must survive monitoring revoke: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeRevoke, "write", []string{"read"}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeRevoke, "read", []string{}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "monitoring", []string{"monitoring"}))
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "monitoring", []string{"monitoring"}))
	assertAllowed("INFO", "server")
	assertDenied("GET", probeKey)
	assertDenied("PUBLISH", "grantor:it:channel", "monitoring-must-not-publish")

	snapshot, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	config, err := adm.ConfigGet(ctx, "aclfile").Result()
	if err != nil {
		t.Fatalf("read persistence configuration: %v", err)
	}
	wantPersistence := "runtime_only"
	if config["aclfile"] != "" {
		wantPersistence = "configured"
	}
	if snapshot.Topology["acl_persistence"] != wantPersistence {
		t.Fatalf("persistence=%v want %s", snapshot.Topology["acl_persistence"], wantPersistence)
	}
	found = false
	for _, binding := range snapshot.Bindings {
		if binding.AccountEngineIdentity == name {
			found = true
			if binding.PermissionExternalID != "monitoring" {
				t.Fatal("monitoring-only account must not acquire another observed binding")
			}
		}
	}
	if !found {
		t.Fatal("monitoring binding must be observed after regrant")
	}
}
