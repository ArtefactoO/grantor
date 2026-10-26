//go:build integration

package kafka_test

import (
	"context"
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
)

func TestConnectionAdminCredentialLifecycle(t *testing.T) {
	ctx := context.Background()
	broker, user, pass := target(t)
	cfg := connection(broker, user, pass)
	manager := kafka.New()
	assessment, err := manager.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		t.Fatalf("AssessConnectionAdminCredential: %v", err)
	}
	if !assessment.SwitchSupported || !assessment.RotateSupported {
		t.Fatalf("assessment = %+v", assessment)
	}
	expected := assessment.Proof()
	snapshot, err := manager.Discover(ctx, cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if caps := manager.CapabilitiesFor(cfg, snapshot.Topology); !slices.Contains(caps, adapter.CapConnectionAdminCredentialRotate) {
		t.Fatalf("capabilities = %v", caps)
	}
	original := cfg.AdminCredential
	candidate := original
	candidate.Secret = []byte("Grantor-Admin-Rotation-Kafka-2026")
	rotated := false
	t.Cleanup(func() {
		if rotated {
			recovery := cfg
			recovery.AdminCredential = candidate
			_, _ = manager.RotateConnectionAdminCredential(context.Background(), recovery, original, expected)
		}
	})
	if _, err := manager.RotateConnectionAdminCredential(ctx, cfg, candidate, expected); err != nil {
		t.Fatalf("RotateConnectionAdminCredential: %v", err)
	}
	rotated = true
	rotatedCfg := cfg
	rotatedCfg.AdminCredential = candidate
	if _, err := manager.RotateConnectionAdminCredential(ctx, rotatedCfg, original, expected); err != nil {
		t.Fatalf("restore original admin credential: %v", err)
	}
	rotated = false
}
