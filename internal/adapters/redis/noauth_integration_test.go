//go:build integration

package redis_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"github.com/ArtefactoO/grantor/internal/adapter"
	redisadapter "github.com/ArtefactoO/grantor/internal/adapters/redis"
)

func TestRedisNoAuthDiscoveryAndPasswordModesAreIndependent(t *testing.T) {
	addr := os.Getenv("GRANTOR_TEST_REDIS_NOAUTH_ADDR")
	if addr == "" {
		t.Skip("GRANTOR_TEST_REDIS_NOAUTH_ADDR is required")
	}
	ctx := t.Context()
	a := redisadapter.New()
	cfg := adapter.Connection{Engine: "redis", AuthMode: "none", Endpoints: []string{addr}, AdminCredential: adapter.Credential{Kind: "none", Username: "default"}}
	if err := a.ValidateConnection(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	snap, err := a.Discover(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Topology["authentication_enabled"] != false || snap.Topology["authentication_disabled"] != true {
		t.Fatalf("missing finding: %v", snap.Topology)
	}
	caps := a.CapabilitiesFor(cfg, snap.Topology)
	if slices.Contains(caps, adapter.CapAccessGrant) || slices.Contains(caps, adapter.CapCredentialRotate) || !slices.Contains(caps, adapter.CapConnectionAdminCredentialSwitch) {
		t.Fatalf("unsafe capabilities %v", caps)
	}
	admin := goredis.NewClient(&goredis.Options{Addr: addr})
	defer admin.Close()
	user := "noauth_" + uuid.NewString()
	const password = "redis-noauth-fixture-password"
	if err := admin.Do(ctx, "ACL", "SETUSER", user, "on", ">"+password, "~*", "&*", "+@all").Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Do(context.Background(), "ACL", "DELUSER", user).Err() })
	pw := cfg
	pw.AuthMode = "password"
	pw.AdminCredential = adapter.Credential{Kind: "password", Username: user, Secret: []byte(password)}
	if err := a.ValidateConnection(ctx, pw); err != nil {
		t.Fatal(err)
	}
	pw.AdminCredential.Secret = []byte("deliberately-wrong-fixture")
	if err := a.ValidateConnection(ctx, pw); err == nil {
		t.Fatal("password mode accepted wrong password")
	}
	// nopass must never be accepted as proof of an arbitrary supplied password.
	pw.AdminCredential = adapter.Credential{Kind: "password", Username: "default", Secret: []byte("fabricated-password")}
	if _, err := a.Discover(ctx, pw); err == nil {
		t.Fatal("password mode accepted nopass default")
	}
	protectedAddr, protectedPass := target(t)
	protected := connection(protectedAddr, protectedPass)
	protected.AuthMode = "none"
	protected.AdminCredential = adapter.Credential{Kind: "none", Username: "default"}
	if _, err := a.Discover(ctx, protected); err == nil {
		t.Fatal("none mode bypassed required authentication")
	}
}
