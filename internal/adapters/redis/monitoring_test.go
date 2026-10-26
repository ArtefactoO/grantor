package redis

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const monitoringCommands = "-@all +ping +info +hello +client|setname +client|setinfo"

func TestMonitoringManagedFormsRemainExact(t *testing.T) {
	for _, tc := range []struct {
		name, rules string
		bundles     []string
	}{
		{"monitoring only", "resetchannels " + monitoringCommands, []string{bundleMonitoring}},
		{"read and monitoring", "~* &* -@all +@read -@dangerous +ping +info +hello +client|setname +client|setinfo", []string{bundleRead, bundleMonitoring}},
		{"write and monitoring", "~* &* -@all +@write -@dangerous +ping +info +hello +client|setname +client|setinfo", []string{bundleWrite, bundleMonitoring}},
		{"read write monitoring", "~* &* -@all +@read +@write -@dangerous +ping +info +hello +client|setname +client|setinfo", []string{bundleRead, bundleWrite, bundleMonitoring}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, err := parseACLListLine("user monitor on " + tc.rules)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			bundles, managed := matchBundles(user)
			if !managed || !slices.Equal(bundles, tc.bundles) {
				t.Fatalf("managed=%v bundles=%v want %v", managed, bundles, tc.bundles)
			}
		})
	}
	for _, extra := range []string{"~*", "&*", "+get", "+scan", "+client", "+client|kill", "+config|get", "+@connection", "(~* -@all +get)", "unknown-token"} {
		t.Run("unmanaged extra "+extra, func(t *testing.T) {
			user, err := parseACLListLine("user monitor on " + monitoringCommands + " " + extra)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, managed := matchBundles(user); managed {
				t.Fatal("extra command, pattern, category or selector must not become managed monitoring")
			}
		})
	}
}

func TestMonitoringDoesNotGrantKeysChannelsOrAdministration(t *testing.T) {
	rules, err := rulesFor([]string{bundleMonitoring})
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	user, err := parseACLListLine("user monitor on " + strings.Join(rules, " "))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(user.root.keys) != 0 || len(user.root.channels) != 0 || aclAdminAllowed(user) || userDangerous(user) {
		t.Fatal("monitoring must not grant patterns or administrative commands")
	}
	for _, command := range []string{"info", "ping", "hello"} {
		if !evalCommand(user.root, command, []string{"slow", "dangerous", "connection"}).full {
			t.Fatalf("monitoring command %q must be allowed explicitly", command)
		}
	}
	for _, command := range []string{"get", "scan", "set", "publish", "acl", "config", "flushall", "shutdown"} {
		if evalCommand(user.root, command, []string{"read", "write", "admin", "connection", "dangerous", "slow"}).full {
			t.Fatalf("monitoring must not allow %q", command)
		}
	}
	client := evalCommand(user.root, "client", []string{"admin", "connection", "dangerous", "slow"})
	if client.full || !client.subs["setname"] || !client.subs["setinfo"] || len(client.subs) != 2 {
		t.Fatalf("client permission=%v; want only client-local handshake subcommands", client)
	}
	found := false
	for _, permission := range bundlePermissions() {
		if permission.ExternalID == bundleMonitoring {
			found = true
		}
		if permission.ExternalID == bundleMonitoring && (!permission.Assignable || permission.Dangerous) {
			t.Fatal("monitoring must be assignable and non-dangerous")
		}
	}
	if !found {
		t.Fatal("monitoring permission must be published")
	}
}

func TestAdminCannotAbsorbMonitoringBinding(t *testing.T) {
	_, err := rulesFor([]string{bundleAdmin, bundleMonitoring})
	if !errors.Is(err, ErrBundleCombination) {
		t.Fatalf("error=%v want rejected non-representable admin combination", err)
	}
}

func TestMonitoringRevokePreservesExplicitReadWriteDesiredState(t *testing.T) {
	user, err := parseACLListLine("user monitor on ~* &* -@all +@read +@write -@dangerous")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	verified, err := verifyAccess(adapter.DesiredChange{
		Kind: adapter.ChangeRevoke, Permission: bundleMonitoring,
		AccountPermissions: []string{bundleRead, bundleWrite},
	}, "monitor", user, true)
	if err != nil || !verified.Verified {
		t.Fatalf("verification=%v error=%v; want both explicit data bundles preserved", verified, err)
	}
	user.root.commands = []string{"-@all"}
	verified, err = verifyAccess(adapter.DesiredChange{
		Kind: adapter.ChangeRevoke, Permission: bundleMonitoring,
		AccountPermissions: []string{bundleRead, bundleWrite},
	}, "monitor", user, true)
	if err != nil || verified.Verified {
		t.Fatal("loss of the other explicitly granted bundles must not verify")
	}
}
