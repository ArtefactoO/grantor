//go:build integration

package mysql_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
)

func TestConnectionAdminCredentialLifecycle(t *testing.T) {
	ctx := context.Background()
	cfg := targetConnection(t, targetDSN(t))
	manager := mysql.New()
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
	candidate.Secret = []byte("Grantor-Admin-Rotation-MySQL-2026")
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

func TestConnectionAdminCredentialRotationWithNoBackslashEscapes(t *testing.T) {
	ctx := context.Background()
	dsn := targetDSN(t)
	db := openTarget(t, dsn, "", "", "")
	defer func() { _ = db.Close() }()
	var originalMode string
	if err := db.QueryRowContext(ctx, `SELECT @@GLOBAL.sql_mode`).Scan(&originalMode); err != nil {
		t.Fatal(err)
	}
	mode := originalMode
	if !strings.Contains(","+mode+",", ",NO_BACKSLASH_ESCAPES,") {
		if mode != "" {
			mode += ","
		}
		mode += "NO_BACKSLASH_ESCAPES"
	}
	modeLiteral := "'" + strings.ReplaceAll(mode, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, `SET GLOBAL sql_mode = `+modeLiteral); err != nil {
		t.Skipf("cannot set NO_BACKSLASH_ESCAPES: %v", err)
	}
	t.Cleanup(func() {
		restore := openTarget(t, dsn, "", "", "")
		defer func() { _ = restore.Close() }()
		originalLiteral := "'" + strings.ReplaceAll(originalMode, "'", "''") + "'"
		_, _ = restore.ExecContext(context.Background(), `SET GLOBAL sql_mode = `+originalLiteral)
	})

	cfg := targetConnection(t, dsn)
	manager := mysql.New()
	assessment, err := manager.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := assessment.Proof()
	original := cfg.AdminCredential
	candidate := original
	candidate.Secret = []byte("Grantor-'quote'-\\literal-2026")
	rotated := false
	t.Cleanup(func() {
		if rotated {
			recovery := cfg
			recovery.AdminCredential = candidate
			_, _ = manager.RotateConnectionAdminCredential(context.Background(), recovery, original, expected)
		}
	})
	if _, err := manager.RotateConnectionAdminCredential(ctx, cfg, candidate, expected); err != nil {
		t.Fatalf("rotate under NO_BACKSLASH_ESCAPES: %v", err)
	}
	rotated = true
	recovery := cfg
	recovery.AdminCredential = candidate
	if _, err := manager.RotateConnectionAdminCredential(ctx, recovery, original, expected); err != nil {
		t.Fatalf("restore after NO_BACKSLASH_ESCAPES: %v", err)
	}
	rotated = false
}

func TestConnectionAdminCredentialRotationDiscardsExistingSecondaryPassword(t *testing.T) {
	ctx := context.Background()
	dsn := targetDSN(t)
	cfg := targetConnection(t, dsn)
	manager := mysql.New()
	original := cfg.AdminCredential
	primary := original
	primary.Secret = []byte("Grantor-temporary-primary-2026")
	db := openTarget(t, dsn, "", "", "")
	if _, err := db.ExecContext(ctx,
		`ALTER USER CURRENT_USER() IDENTIFIED BY 'Grantor-temporary-primary-2026' RETAIN CURRENT PASSWORD`); err != nil {
		_ = db.Close()
		t.Skipf("dual passwords are unavailable: %v", err)
	}
	_ = db.Close()
	assessment, err := manager.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected := assessment.Proof()
	t.Cleanup(func() {
		for _, current := range []adapter.Credential{primary, original} {
			recovery := cfg
			recovery.AdminCredential = current
			if _, err := manager.RotateConnectionAdminCredential(context.Background(), recovery, original, expected); err == nil {
				return
			}
		}
	})

	// Canonical old credential is now the secondary password. Rotation must
	// still reach DISCARD OLD PASSWORD before demanding deterministic old
	// rejection.
	candidate := original
	candidate.Secret = []byte("Grantor-dual-cleanup-candidate-2026")
	if _, err := manager.RotateConnectionAdminCredential(ctx, cfg, candidate, expected); err != nil {
		t.Fatalf("rotate from secondary canonical password: %v", err)
	}
	if _, err := manager.ProveConnectionAdminCredential(ctx, cfg, original); !errors.Is(err, adapter.ErrAdminCredentialRejected) {
		t.Fatalf("old secondary credential error=%v, want deterministic rejection", err)
	}
	recovery := cfg
	recovery.AdminCredential = candidate
	if _, err := manager.RotateConnectionAdminCredential(ctx, recovery, original, expected); err != nil {
		t.Fatalf("restore original after dual-password test: %v", err)
	}
}
