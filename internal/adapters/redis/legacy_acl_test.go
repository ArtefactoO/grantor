package redis

import (
	"slices"
	"strings"
	"testing"
)

func TestLegacyACLMatchesCompleteCommandSetAndNoSurplus(t *testing.T) {
	catalog := map[string][]string{
		"get": {"read"}, "keys": {"read", "dangerous"},
		"set": {"write"}, "flushall": {"write", "dangerous"},
		"info": {"slow", "dangerous"}, "ping": {"connection"},
		"hello": {"connection"}, "client": {"connection", "admin", "dangerous"},
		"acl": {"admin", "dangerous"},
	}
	for _, tc := range []struct {
		name, commands string
		want           []string
	}{
		{"6.2 read rewrite", "-@all +@read -keys", []string{bundleRead}},
		{"expanded write", "-@all +set", []string{bundleWrite}},
		{"read monitoring", "-@all +@read -keys +ping +info +hello +client|setname +client|setinfo", []string{bundleRead, bundleMonitoring}},
		{"extra admin command", "-@all +@read -keys +acl", nil},
		{"dangerous category not removed", "-@all +@read", nil},
		{"full client command", "-@all +@read -keys +client", nil},
		{"additional client subcommand", "-@all +@read -keys +client|kill", nil},
		{"unknown command", "-@all +@read -keys +future-module-command", nil},
		{"unknown category", "-@all +@read -keys +@future", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var selector aclSelector
			var unknown []string
			classifySelectorTokens(strings.Fields(tc.commands), &selector, &unknown)
			got, managed := matchLegacyCommandSet(selector, catalog)
			if managed != (tc.want != nil) || !slices.Equal(got, tc.want) {
				t.Fatalf("managed=%v bundles=%v want %v", managed, got, tc.want)
			}
		})
	}
	var selector aclSelector
	var unknown []string
	classifySelectorTokens([]string{"-@all", "+@read", "-keys"}, &selector, &unknown)
	if _, managed := matchLegacyCommandSet(selector, nil); managed {
		t.Fatal("unavailable command metadata must never prove managed permissions")
	}
}
