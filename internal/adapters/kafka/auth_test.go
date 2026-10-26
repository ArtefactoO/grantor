package kafka

import (
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/secret"
)

// connWith собирает connection с заданными TLS-режимом и auth-атрибутами.
func connWith(tlsMode string, attrs map[string]any) adapter.Connection {
	return adapter.Connection{
		Engine:     Engine,
		Endpoints:  []string{"kafka.example.com:9092"},
		TLS:        adapter.TLSConfig{Mode: tlsMode},
		Attributes: attrs,
	}
}

func TestParseAuthConfigMatrixAndInference(t *testing.T) {
	tests := []struct {
		name     string
		tlsMode  string
		attrs    map[string]any
		wantMech saslMechanism
		wantProt securityProtocol
	}{
		{
			name:     "backward compat: unset mechanism defaults to scram-sha-256 over plaintext",
			tlsMode:  "disabled",
			attrs:    nil,
			wantMech: mechScramSha256,
			wantProt: protoSASLPlaintext,
		},
		{
			name:     "backward compat: unset mechanism with TLS infers sasl_ssl",
			tlsMode:  "verify-full",
			attrs:    nil,
			wantMech: mechScramSha256,
			wantProt: protoSASLSSL,
		},
		{
			name:     "plain over plaintext (inferred)",
			tlsMode:  "disabled",
			attrs:    map[string]any{attrSASLMechanism: "plain"},
			wantMech: mechPlain,
			wantProt: protoSASLPlaintext,
		},
		{
			name:     "plain over TLS (inferred sasl_ssl)",
			tlsMode:  "require",
			attrs:    map[string]any{attrSASLMechanism: "plain"},
			wantMech: mechPlain,
			wantProt: protoSASLSSL,
		},
		{
			name:     "scram-sha-512 explicit",
			tlsMode:  "disabled",
			attrs:    map[string]any{attrSASLMechanism: "scram-sha-512"},
			wantMech: mechScramSha512,
			wantProt: protoSASLPlaintext,
		},
		{
			name:     "none + TLS infers ssl (mTLS)",
			tlsMode:  "verify-full",
			attrs:    map[string]any{attrSASLMechanism: "none"},
			wantMech: mechNone,
			wantProt: protoSSL,
		},
		{
			name:     "none + no TLS infers plaintext",
			tlsMode:  "disabled",
			attrs:    map[string]any{attrSASLMechanism: "none"},
			wantMech: mechNone,
			wantProt: protoPlaintext,
		},
		{
			name:     "explicit security_protocol matching mechanism/tls",
			tlsMode:  "verify-full",
			attrs:    map[string]any{attrSASLMechanism: "scram-sha-256", attrSecurityProtocol: "sasl_ssl"},
			wantMech: mechScramSha256,
			wantProt: protoSASLSSL,
		},
		{
			name:     "uppercase mechanism is normalized",
			tlsMode:  "disabled",
			attrs:    map[string]any{attrSASLMechanism: "SCRAM-SHA-256"},
			wantMech: mechScramSha256,
			wantProt: protoSASLPlaintext,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac, err := parseAuthConfig(connWith(tt.tlsMode, tt.attrs))
			if err != nil {
				t.Fatalf("parseAuthConfig: %v", err)
			}
			if ac.mechanism != tt.wantMech {
				t.Errorf("mechanism = %q, want %q", ac.mechanism, tt.wantMech)
			}
			if ac.protocol != tt.wantProt {
				t.Errorf("protocol = %q, want %q", ac.protocol, tt.wantProt)
			}
		})
	}
}

func TestParseAuthConfigCoherenceErrors(t *testing.T) {
	tests := []struct {
		name    string
		tlsMode string
		attrs   map[string]any
		wantSub string
	}{
		{
			name:    "sasl_ssl requires TLS",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "scram-sha-256", attrSecurityProtocol: "sasl_ssl"},
			wantSub: "requires tls mode != disabled",
		},
		{
			name:    "ssl requires TLS",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "none", attrSecurityProtocol: "ssl"},
			wantSub: "requires tls mode != disabled",
		},
		{
			name:    "sasl_plaintext forbids TLS",
			tlsMode: "require",
			attrs:   map[string]any{attrSASLMechanism: "plain", attrSecurityProtocol: "sasl_plaintext"},
			wantSub: "requires tls mode disabled",
		},
		{
			name:    "sasl_plaintext requires a mechanism",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "none", attrSecurityProtocol: "sasl_plaintext"},
			wantSub: "requires a SASL mechanism",
		},
		{
			name:    "plaintext forbids a mechanism",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "scram-sha-256", attrSecurityProtocol: "plaintext"},
			wantSub: "cannot be combined with sasl mechanism",
		},
		{
			name:    "unknown mechanism",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "kerberos"},
			wantSub: "unknown sasl mechanism",
		},
		{
			name:    "gssapi is out of scope",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "gssapi"},
			wantSub: "is not supported",
		},
		{
			name:    "oauthbearer is out of scope",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSASLMechanism: "oauthbearer"},
			wantSub: "is not supported",
		},
		{
			name:    "unknown security protocol",
			tlsMode: "disabled",
			attrs:   map[string]any{attrSecurityProtocol: "kerberos_ssl"},
			wantSub: "unknown security protocol",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseAuthConfig(connWith(tt.tlsMode, tt.attrs))
			if err == nil {
				t.Fatalf("parseAuthConfig: expected error containing %q", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestAuthConfigManagesScram(t *testing.T) {
	tests := []struct {
		mech saslMechanism
		want bool
	}{
		{mechScramSha256, true},
		{mechScramSha512, true},
		{mechPlain, false},
		{mechNone, false},
	}
	for _, tt := range tests {
		ac := authConfig{mechanism: tt.mech}
		if got := ac.managesScram(); got != tt.want {
			t.Errorf("managesScram(%q) = %v, want %v", tt.mech, got, tt.want)
		}
	}
}

// TestSaslMechanismSelection проверяет соответствие механизма подключения
// механизму franz-go по его Name() — исчерпывающе по всем значениям.
func TestSaslMechanismSelection(t *testing.T) {
	sec := secret.New([]byte("pw"))
	tests := []struct {
		mech     saslMechanism
		wantName string
		wantSASL bool
	}{
		{mechPlain, "PLAIN", true},
		{mechScramSha256, "SCRAM-SHA-256", true},
		{mechScramSha512, "SCRAM-SHA-512", true},
		{mechNone, "", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.mech), func(t *testing.T) {
			ac := authConfig{mechanism: tt.mech}
			mech, ok := ac.saslMechanism("admin", sec)
			if ok != tt.wantSASL {
				t.Fatalf("saslMechanism ok = %v, want %v", ok, tt.wantSASL)
			}
			if !tt.wantSASL {
				if mech != nil {
					t.Errorf("mechanism = %v, want nil for %q", mech, tt.mech)
				}
				return
			}
			if mech.Name() != tt.wantName {
				t.Errorf("mechanism name = %q, want %q", mech.Name(), tt.wantName)
			}
		})
	}
}

func TestUsesTLSAndSASL(t *testing.T) {
	tests := []struct {
		proto    securityProtocol
		wantSASL bool
		wantTLS  bool
	}{
		{protoPlaintext, false, false},
		{protoSASLPlaintext, true, false},
		{protoSASLSSL, true, true},
		{protoSSL, false, true},
	}
	for _, tt := range tests {
		ac := authConfig{protocol: tt.proto}
		if ac.usesSASL() != tt.wantSASL {
			t.Errorf("usesSASL(%q) = %v, want %v", tt.proto, ac.usesSASL(), tt.wantSASL)
		}
		if ac.usesTLS() != tt.wantTLS {
			t.Errorf("usesTLS(%q) = %v, want %v", tt.proto, ac.usesTLS(), tt.wantTLS)
		}
	}
}
