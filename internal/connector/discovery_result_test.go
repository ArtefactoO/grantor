package connector

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestDiscoveryResultNegotiationPreservesACLMetadata(t *testing.T) {
	snapshot := &adapter.Snapshot{ServerVersion: "16", IncompleteScopes: []string{"db:temporarily-unavailable"},
		Topology: map[string]any{"postgres_object_acl_version": 1, "postgres_default_privileges": []any{map[string]any{"grantee": "alice", "privilege": "SELECT"}}}}
	for range 500 {
		snapshot.Permissions = append(snapshot.Permissions, adapter.ObservedPermission{ExternalID: "repeated-object-privilege", Name: "SELECT ON app.public.items", Attributes: map[string]any{"kind": "postgres_object_privilege"}})
	}
	plain, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := MarshalDiscoveryResult(snapshot, "")
	if err != nil || !bytes.Equal(plain, legacy) {
		t.Fatal("legacy request no longer receives a plain snapshot")
	}
	encoded, err := MarshalDiscoveryResult(snapshot, SnapshotGzipV1)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= len(plain)/2 {
		t.Fatal("repeated ACL catalog was not compressed")
	}
	for _, raw := range []json.RawMessage{plain, encoded} {
		got, err := ParseDiscoveryResult(raw)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got)
		if !bytes.Equal(b, plain) {
			t.Fatal("discovery transport lost ACL metadata or incomplete scopes")
		}
	}
}

func TestDiscoveryResultRejectsCorruptionAndBoundedExpansion(t *testing.T) {
	for _, raw := range []json.RawMessage{[]byte(`null`), []byte(`{}`), []byte(`{"snapshot_encoding":"unknown","data":"AA=="}`), []byte(`{"snapshot_encoding":"gzip-v1","data":"AA=="}`), []byte(`{"snapshot_encoding":"gzip-v1","data":"AA==","raw_sql":"arbitrary"}`)} {
		if _, err := ParseDiscoveryResult(raw); err == nil {
			t.Fatal("invalid discovery result became a valid empty snapshot")
		}
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDiscoveryGzip(compressed.Bytes(), 512); err == nil {
		t.Fatal("decompression exceeded its declared memory bound")
	}
}
