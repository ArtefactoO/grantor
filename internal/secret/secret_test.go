package secret_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/secret"
)

const marker = "s3cr3t-marker-value"

func TestFormattingRedacts(t *testing.T) {
	v := secret.FromString(marker)

	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%d", "%x", "%q"} {
		if got := fmt.Sprintf(verb, v); got != "[REDACTED]" {
			t.Errorf("Sprintf(%q, Value) = %q, want [REDACTED]", verb, got)
		}
		if got := fmt.Sprintf(verb, &v); got != "[REDACTED]" {
			t.Errorf("Sprintf(%q, *Value) = %q, want [REDACTED]", verb, got)
		}
	}

	if got := v.String(); got != "[REDACTED]" {
		t.Errorf("String() = %q, want [REDACTED]", got)
	}
	if got := v.GoString(); got != "[REDACTED]" {
		t.Errorf("GoString() = %q, want [REDACTED]", got)
	}
}

func TestJSONRedacts(t *testing.T) {
	v := secret.FromString(marker)

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(Value): %v", err)
	}
	if string(b) != `"[REDACTED]"` {
		t.Errorf("json.Marshal(Value) = %s, want \"[REDACTED]\"", b)
	}

	wrapped := struct {
		Password secret.Value  `json:"password"`
		Ptr      *secret.Value `json:"ptr"`
	}{Password: v, Ptr: &v}

	b, err = json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("json.Marshal(struct): %v", err)
	}
	if strings.Contains(string(b), marker) {
		t.Error("json.Marshal(struct): output contains secret marker")
	}
	if !strings.Contains(string(b), "[REDACTED]") {
		t.Errorf("json.Marshal(struct) = %s, want [REDACTED] placeholders", b)
	}
}

func TestSlogRedacts(t *testing.T) {
	v := secret.FromString(marker)
	var buf bytes.Buffer

	text := slog.New(slog.NewTextHandler(&buf, nil))
	text.Info("credential", "password", v, "ptr", &v, slog.Any("value", v))
	if strings.Contains(buf.String(), marker) {
		t.Error("slog text output contains secret marker")
	}
	if !strings.Contains(buf.String(), "[REDACTED]") {
		t.Errorf("slog text output = %q, want [REDACTED] placeholders", buf.String())
	}

	buf.Reset()
	jsonLog := slog.New(slog.NewJSONHandler(&buf, nil))
	jsonLog.Info("credential", "password", v, "ptr", &v)
	if strings.Contains(buf.String(), marker) {
		t.Error("slog json output contains secret marker")
	}
}

func TestRevealReturnsCopy(t *testing.T) {
	v := secret.New([]byte(marker))

	got := v.Reveal()
	if !bytes.Equal(got, []byte(marker)) {
		t.Fatalf("Reveal() = %q, want %q", got, marker)
	}

	// Мутация результата Reveal не должна менять секрет.
	got[0] = 'X'
	if !bytes.Equal(v.Reveal(), []byte(marker)) {
		t.Error("Reveal() must return a copy of the secret")
	}

	if v.RevealString() != marker {
		t.Errorf("RevealString() = %q, want %q", v.RevealString(), marker)
	}
}

func TestNewCopiesInput(t *testing.T) {
	src := []byte(marker)
	v := secret.New(src)

	// Мутация исходного слайса не должна менять секрет.
	src[0] = 'X'
	if v.RevealString() != marker {
		t.Errorf("RevealString() after source mutation = %q, want %q", v.RevealString(), marker)
	}
}

func TestWipe(t *testing.T) {
	v := secret.New([]byte(marker))
	w := v // копия разделяет внутренний буфер

	v.Wipe()

	if !v.IsZero() {
		t.Error("IsZero() after Wipe = false, want true")
	}
	if got := v.Reveal(); len(got) != 0 {
		t.Errorf("Reveal() after Wipe = %q, want empty", got)
	}

	// Буфер именно занулён, а не просто отвязан: копия видит нули.
	got := w.Reveal()
	if len(got) != len(marker) {
		t.Fatalf("copy Reveal() length = %d, want %d", len(got), len(marker))
	}
	if !bytes.Equal(got, make([]byte, len(marker))) {
		t.Error("Wipe must zero the shared buffer")
	}
}

func TestIsZero(t *testing.T) {
	var zero secret.Value
	if !zero.IsZero() {
		t.Error("zero Value: IsZero() = false, want true")
	}
	if !secret.FromString("").IsZero() {
		t.Error("FromString(empty): IsZero() = false, want true")
	}
	if secret.FromString("x").IsZero() {
		t.Error("FromString(x): IsZero() = true, want false")
	}
}
