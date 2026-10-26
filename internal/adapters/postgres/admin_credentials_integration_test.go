//go:build integration

package postgres_test

import (
	"context"
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
)

func TestConnectionAdminCredentialLifecycle(t *testing.T) {
	ctx := context.Background()
	cfg := targetConnection(t, targetDSN(t))
	manager := postgres.New()
	assessment, err := manager.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		t.Fatalf("AssessConnectionAdminCredential: %v", err)
	}
	if !assessment.SwitchSupported || !assessment.RotateSupported ||
		assessment.CanonicalIdentity != cfg.AdminCredential.Username {
		t.Fatalf("assessment = %+v", assessment)
	}
	expected := assessment.Proof()
	snapshot, err := manager.Discover(ctx, cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, ok := adapter.AdminCredentialAssessmentFromTopology(snapshot.Topology); !ok {
		t.Fatalf("topology does not carry admin proof: %+v", snapshot.Topology)
	}
	if caps := manager.CapabilitiesFor(cfg, snapshot.Topology); !slices.Contains(caps, adapter.CapConnectionAdminCredentialRotate) {
		t.Fatalf("capabilities = %v", caps)
	}

	original := cfg.AdminCredential
	candidate := original
	candidate.Secret = []byte("Grantor-Admin-Rotation-PG-2026")
	rotated := false
	t.Cleanup(func() {
		if !rotated {
			return
		}
		recovery := cfg
		recovery.AdminCredential = candidate
		_, _ = manager.RotateConnectionAdminCredential(context.Background(), recovery, original, expected)
	})
	if _, err := manager.RotateConnectionAdminCredential(ctx, cfg, candidate, expected); err != nil {
		t.Fatalf("RotateConnectionAdminCredential: %v", err)
	}
	rotated = true
	recovered, err := manager.RotateConnectionAdminCredential(ctx, cfg, candidate, expected)
	if err != nil || !recovered.AlreadyApplied {
		t.Fatalf("lost-response retry = %+v, %v", recovered, err)
	}
	rotatedCfg := cfg
	rotatedCfg.AdminCredential = candidate
	if _, err := manager.ProveConnectionAdminCredential(ctx, rotatedCfg, candidate); err != nil {
		t.Fatalf("prove candidate: %v", err)
	}
	if _, err := manager.RotateConnectionAdminCredential(ctx, rotatedCfg, original, expected); err != nil {
		t.Fatalf("restore original admin credential: %v", err)
	}
	rotated = false
}
