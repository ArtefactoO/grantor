package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/audit"
)

// TestLogEventEmitsStructuredEvent проверяет, что событие сериализуется в
// одну JSON-строку с маркером audit=true, всеми ссылочными id и вложенным
// (не строковым и не base64) объектом metadata.
func TestLogEventEmitsStructuredEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	w := audit.NewWriter().WithLogger(logger)

	connID := uuid.New()
	resID := uuid.New()
	prinID := uuid.New()
	accID := uuid.New()
	opID := uuid.New()

	w.LogEvent(context.Background(), audit.Event{
		ActorType:    "user",
		ActorID:      "operator@grantor.dev",
		Action:       "credential.rotated",
		ConnectionID: &connID,
		ResourceID:   &resID,
		PrincipalID:  &prinID,
		AccountID:    &accID,
		OperationID:  &opID,
		Result:       "success",
		Metadata:     []byte(`{"channel":"yopass","one_time":true}`),
	})

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected a log line, got none")
	}
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("expected exactly one log line, got: %q", line)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", err, line)
	}

	if got["audit"] != true {
		t.Errorf("audit marker = %v, want true", got["audit"])
	}
	if got["msg"] != "audit event" {
		t.Errorf("msg = %v, want %q", got["msg"], "audit event")
	}
	if got["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", got["level"])
	}
	for k, want := range map[string]string{
		"action":        "credential.rotated",
		"actor_type":    "user",
		"actor_id":      "operator@grantor.dev",
		"result":        "success",
		"connection_id": connID.String(),
		"resource_id":   resID.String(),
		"principal_id":  prinID.String(),
		"account_id":    accID.String(),
		"operation_id":  opID.String(),
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %q", k, got[k], want)
		}
	}
	if _, ok := got["occurred_at"]; !ok {
		t.Error("occurred_at is missing")
	}

	// metadata обязана быть вложенным JSON-объектом, а не строкой/base64.
	meta, ok := got["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is not a nested object: %T (%v)", got["metadata"], got["metadata"])
	}
	if meta["channel"] != "yopass" || meta["one_time"] != true {
		t.Errorf("metadata = %v, want channel=yopass one_time=true", meta)
	}
}

// TestLogEventMinimalEventOmitsNilRefs проверяет, что незаданные ссылочные
// id опускаются, а пустая metadata нормализуется в пустой объект.
func TestLogEventMinimalEventOmitsNilRefs(t *testing.T) {
	var buf bytes.Buffer
	w := audit.NewWriter().WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))

	w.LogEvent(context.Background(), audit.Event{
		ActorType: "service",
		ActorID:   "grantor-worker",
		Action:    "connection.discovered",
		Result:    "success",
	})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", err, buf.String())
	}
	for _, k := range []string{"connection_id", "resource_id", "principal_id", "account_id", "operation_id"} {
		if _, ok := got[k]; ok {
			t.Errorf("nil reference %s must be omitted, got %v", k, got[k])
		}
	}
	meta, ok := got["metadata"].(map[string]any)
	if !ok || len(meta) != 0 {
		t.Errorf("metadata = %v, want empty object", got["metadata"])
	}
}

// TestLogEventDisabledLoggerIsNoop проверяет обратную совместимость: Writer
// без logger (и с явным nil) ничего не пишет и не паникует.
func TestLogEventDisabledLoggerIsNoop(t *testing.T) {
	ev := audit.Event{ActorType: "user", ActorID: "a@b.c", Action: "principal.created", Result: "success"}

	// NewWriter без WithLogger — дублирование выключено по умолчанию.
	audit.NewWriter().LogEvent(context.Background(), ev)

	// Явный nil logger — тоже no-op.
	audit.NewWriter().WithLogger(nil).LogEvent(context.Background(), ev)
}

// TestLogEventOnlyEmitsProvidedMetadata фиксирует контракт: в log stream
// уходят ровно переданные (sanitized) поля metadata и никаких секретов из
// иных источников. Metadata пакета уже sanitized, поэтому тест сторожит
// именно проекцию — отсутствие утечки секретных ключей в вывод.
func TestLogEventOnlyEmitsProvidedMetadata(t *testing.T) {
	var buf bytes.Buffer
	w := audit.NewWriter().WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))

	w.LogEvent(context.Background(), audit.Event{
		ActorType: "user",
		ActorID:   "admin@grantor.dev",
		Action:    "account.created",
		Result:    "success",
		Metadata:  []byte(`{"username":"svc_reader","engine":"postgres"}`),
	})

	out := buf.String()
	for _, secretKey := range []string{"password", "secret", "token", "private_key", "credential_value"} {
		if strings.Contains(out, secretKey) {
			t.Errorf("log output must not contain secret-like key %q; got: %s", secretKey, out)
		}
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", err, out)
	}
	meta, ok := got["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is not a nested object: %T", got["metadata"])
	}
	if meta["username"] != "svc_reader" || meta["engine"] != "postgres" {
		t.Errorf("metadata = %v, want username=svc_reader engine=postgres", meta)
	}
}
