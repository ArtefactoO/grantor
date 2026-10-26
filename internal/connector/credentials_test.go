package connector_test

import (
	"bytes"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

// TestCredentialsFrameBinding — кадр credentials привязывается к заданию по
// JobID и Nonce из подписанного Job; чужая привязка отклоняется Matches.
func TestCredentialsFrameBinding(t *testing.T) {
	job := sampleJob()
	creds := connector.JobCredentials{
		Admin:   &adapter.Credential{Kind: "password", Username: "admin", Secret: []byte("pw")},
		Account: &adapter.Credential{Kind: "password", Username: "svc", Secret: []byte("acct-pw")},

		AdminCredentialIncarnation: 11,
		AccountVaultVersion:        7,
	}
	frame := creds.Frame(job)
	if frame.JobID != job.ID || frame.Nonce != job.Nonce {
		t.Errorf("frame binding = {%q %q}, want {%q %q}", frame.JobID, frame.Nonce, job.ID, job.Nonce)
	}
	if !frame.Matches(job) {
		t.Error("frame must match its job")
	}
	other := sampleJob()
	other.Nonce = "other-nonce"
	if frame.Matches(other) {
		t.Error("frame must not match a job with another nonce")
	}
	if frame.Admin == nil || frame.Admin.Username != "admin" ||
		frame.AdminCredentialIncarnation != 11 ||
		frame.Account == nil || frame.Account.Username != "svc" || frame.AccountVaultVersion != 7 {
		t.Errorf("frame does not mirror credentials: %+v", frame)
	}
	got := frame.Account.Credential()
	if got.Kind != "password" || got.Username != "svc" || string(got.Secret) != "acct-pw" {
		t.Errorf("frame credential round-trip mismatch: %+v", got)
	}
}

// TestCredentialsZeroSharesMemory — Zero кадра зануляет и материал control
// plane (слайсы разделяются, копий секретов нет), включая adapter.Credential,
// восстановленный из кадра.
func TestCredentialsZeroSharesMemory(t *testing.T) {
	adminSecret := []byte("admin-pw")
	accountSecret := []byte("account-pw")
	creds := connector.JobCredentials{
		Admin:   &adapter.Credential{Kind: "password", Username: "admin", Secret: adminSecret},
		Account: &adapter.Credential{Kind: "password", Username: "svc", Secret: accountSecret},
	}
	frame := creds.Frame(sampleJob())
	fromFrame := frame.Account.Credential()

	frame.Zero()
	for name, b := range map[string][]byte{
		"admin (worker side)":     adminSecret,
		"account (worker side)":   accountSecret,
		"account (adapter side)":  fromFrame.Secret,
		"admin (frame side)":      frame.Admin.Secret,
		"account (frame side)":    frame.Account.Secret,
		"admin (job credentials)": creds.Admin.Secret,
	} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s secret is not zeroed after frame.Zero: %q", name, b)
		}
	}

	// Zero стороны control plane симметричен.
	creds2 := connector.JobCredentials{
		Admin: &adapter.Credential{Kind: "password", Username: "admin", Secret: []byte("pw-2")},
	}
	creds2.Zero()
	if !bytes.Equal(creds2.Admin.Secret, make([]byte, len(creds2.Admin.Secret))) {
		t.Error("JobCredentials.Zero did not zero the admin secret")
	}
}
