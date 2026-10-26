package adapter

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func adminProof(identity, authority string) AdminCredentialProof {
	return AdminCredentialProof{CanonicalIdentity: identity, AuthorityFingerprint: authority, TargetIdentity: "target"}
}

func TestRunCandidateFirstAdminCredentialRotation(t *testing.T) {
	old := Credential{Kind: "password", Username: "admin", Secret: []byte("old")}
	candidate := Credential{Kind: "password", Username: "admin", Secret: []byte("candidate")}

	t.Run("mutates only after deterministic candidate rejection", func(t *testing.T) {
		current := "old"
		applyCalls := 0
		var applyProof AdminCredentialProof
		result, err := RunCandidateFirstAdminCredentialRotation(t.Context(), old, candidate,
			adminProof("admin", "authority"), AdminCredentialRotationHooks{
				Prove: func(_ context.Context, credential Credential) (AdminCredentialProof, error) {
					if string(credential.Secret) != current {
						return AdminCredentialProof{}, ErrAdminCredentialRejected
					}
					return adminProof("admin", "authority"), nil
				},
				Apply: func(_ context.Context, credential Credential, oldProof AdminCredentialProof) error {
					applyCalls++
					applyProof = oldProof
					current = string(credential.Secret)
					return nil
				},
			})
		if err != nil || result.AlreadyApplied || applyCalls != 1 || applyProof != adminProof("admin", "authority") {
			t.Fatalf("result/error/applyCalls = %+v/%v/%d", result, err, applyCalls)
		}
	})

	t.Run("recovers lost response without mutation", func(t *testing.T) {
		applyCalls := 0
		result, err := RunCandidateFirstAdminCredentialRotation(t.Context(), old, candidate,
			adminProof("admin", "authority"), AdminCredentialRotationHooks{
				Prove: func(_ context.Context, credential Credential) (AdminCredentialProof, error) {
					if string(credential.Secret) == "candidate" {
						return adminProof("admin", "authority"), nil
					}
					return AdminCredentialProof{}, ErrAdminCredentialRejected
				},
				Apply: func(context.Context, Credential, AdminCredentialProof) error { applyCalls++; return nil },
			})
		if err != nil || !result.AlreadyApplied || applyCalls != 0 {
			t.Fatalf("result/error/applyCalls = %+v/%v/%d", result, err, applyCalls)
		}
	})

	t.Run("ambiguous candidate never mutates", func(t *testing.T) {
		applyCalls := 0
		_, err := RunCandidateFirstAdminCredentialRotation(t.Context(), old, candidate,
			adminProof("admin", "authority"), AdminCredentialRotationHooks{
				Prove: func(context.Context, Credential) (AdminCredentialProof, error) {
					return AdminCredentialProof{}, ErrAdminCredentialProofAmbiguous
				},
				Apply: func(context.Context, Credential, AdminCredentialProof) error { applyCalls++; return nil },
			})
		if !errors.Is(err, ErrAdminCredentialProofAmbiguous) || applyCalls != 0 {
			t.Fatalf("error/applyCalls = %v/%d", err, applyCalls)
		}
	})

	t.Run("requires old invalidation", func(t *testing.T) {
		_, err := RunCandidateFirstAdminCredentialRotation(t.Context(), old, candidate,
			adminProof("admin", "authority"), AdminCredentialRotationHooks{
				Prove: func(context.Context, Credential) (AdminCredentialProof, error) {
					return adminProof("admin", "authority"), nil
				},
				Apply: func(context.Context, Credential, AdminCredentialProof) error { return nil },
			})
		if !errors.Is(err, ErrAdminCredentialOldStillValid) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("expected fence mismatch never mutates", func(t *testing.T) {
		applyCalls := 0
		_, err := RunCandidateFirstAdminCredentialRotation(t.Context(), old, candidate,
			adminProof("admin", "expected-authority"), AdminCredentialRotationHooks{
				Prove: func(_ context.Context, credential Credential) (AdminCredentialProof, error) {
					if string(credential.Secret) == "candidate" {
						return AdminCredentialProof{}, ErrAdminCredentialRejected
					}
					return adminProof("admin", "actual-authority"), nil
				},
				Apply: func(context.Context, Credential, AdminCredentialProof) error {
					applyCalls++
					return nil
				},
			})
		if !errors.Is(err, ErrAdminCredentialAuthorityChanged) || applyCalls != 0 {
			t.Fatalf("error/applyCalls = %v/%d", err, applyCalls)
		}
	})
}

func TestAdminCredentialAssessmentTopologyRoundTrip(t *testing.T) {
	topology := map[string]any{}
	want := AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: true,
		CanonicalIdentity: "admin", AuthorityFingerprint: "authority", TargetIdentity: "target",
	}
	PublishAdminCredentialAssessment(topology, want)
	got, ok := AdminCredentialAssessmentFromTopology(topology)
	if !ok || got != want {
		t.Fatalf("assessment/ok = %+v/%v, want %+v/true", got, ok, want)
	}
	PublishAdminCredentialAssessment(topology, AdminCredentialAssessment{BlockedReason: "failed"})
	if _, ok := topology[TopologyAdminCredentialCanonicalIdentity]; ok {
		t.Fatal("stale canonical identity was not deleted")
	}
	if _, ok := topology[TopologyAdminCredentialAuthorityFingerprint]; ok {
		t.Fatal("stale authority fingerprint was not deleted")
	}
	if _, ok := topology[TopologyAdminCredentialTargetIdentity]; ok {
		t.Fatal("stale target identity was not deleted")
	}
}

func TestScopeAdminCredentialCapabilitiesRequiresLiveAssessment(t *testing.T) {
	manifest := []Capability{
		CapInventoryAccounts,
		CapConnectionAdminCredentialSwitch,
		CapConnectionAdminCredentialRotate,
	}
	if got := ScopeAdminCredentialCapabilities(manifest, nil); !slices.Equal(got, []Capability{CapInventoryAccounts}) {
		t.Fatalf("capabilities before assessment = %v", got)
	}
	topology := map[string]any{
		TopologyAdminCredentialSwitchSupported: true,
		TopologyAdminCredentialRotateSupported: false,
	}
	if got := ScopeAdminCredentialCapabilities(manifest, topology); !slices.Equal(got,
		[]Capability{CapInventoryAccounts, CapConnectionAdminCredentialSwitch}) {
		t.Fatalf("switch-only capabilities = %v", got)
	}
}
