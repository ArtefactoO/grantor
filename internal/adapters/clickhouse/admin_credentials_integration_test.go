//go:build integration

package clickhouse_test

import (
	"context"
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/clickhouse"
)

func TestConnectionAdminCredentialAssessment(t *testing.T) {
	ctx := context.Background()
	rawURL, _, _, _ := target(t)
	cfg := connectionFromURL(t, rawURL)
	manager := clickhouse.New()
	assessment, err := manager.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		t.Fatalf("AssessConnectionAdminCredential: %v", err)
	}
	if !assessment.SwitchSupported {
		t.Fatalf("assessment = %+v", assessment)
	}
	snapshot, err := manager.Discover(ctx, cfg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	caps := manager.CapabilitiesFor(cfg, snapshot.Topology)
	if !slices.Contains(caps, adapter.CapConnectionAdminCredentialSwitch) {
		t.Fatalf("capabilities = %v", caps)
	}
	if assessment.RotateSupported != slices.Contains(caps, adapter.CapConnectionAdminCredentialRotate) {
		t.Fatalf("assessment/capabilities mismatch: %+v / %v", assessment, caps)
	}
}
