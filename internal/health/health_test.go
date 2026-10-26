package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doRequest выполняет запрос к handler и возвращает записанный ответ.
func doRequest(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

// decodeBody разбирает JSON-ответ readiness handler.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) readyResponse {
	t.Helper()
	var body readyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestLiveHandlerAlwaysOK(t *testing.T) {
	rec := doRequest(t, LiveHandler())
	if rec.Code != http.StatusOK {
		t.Fatalf("live status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := decodeBody(t, rec); body.Status != "ok" {
		t.Fatalf("live body status = %q, want %q", body.Status, "ok")
	}
}

func TestHandlerNoChecksOK(t *testing.T) {
	rec := doRequest(t, Handler())
	if rec.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := decodeBody(t, rec)
	if body.Status != "ok" {
		t.Fatalf("ready body status = %q, want %q", body.Status, "ok")
	}
	if len(body.Failed) != 0 {
		t.Fatalf("ready body failed = %v, want empty", body.Failed)
	}
}

func TestHandlerReportsFailedCheckNames(t *testing.T) {
	okProbe := func(context.Context) error { return nil }
	failProbe := func(context.Context) error {
		return errors.New("dial tcp: secret-host:5432 refused")
	}

	rec := doRequest(t, Handler(
		Check{Name: "postgres", Probe: okProbe},
		Check{Name: "vault", Probe: failProbe},
	))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := decodeBody(t, rec)
	if body.Status != "unavailable" {
		t.Fatalf("ready body status = %q, want %q", body.Status, "unavailable")
	}
	if len(body.Failed) != 1 || body.Failed[0] != "vault" {
		t.Fatalf("ready body failed = %v, want [vault]", body.Failed)
	}
	// Текст ошибки probe не должен утекать в HTTP-ответ.
	if strings.Contains(rec.Body.String(), "secret-host") {
		t.Fatalf("response leaks probe error text: %q", rec.Body.String())
	}
}

func TestHandlerProbeTimeout(t *testing.T) {
	oldTimeout := probeTimeout
	probeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { probeTimeout = oldTimeout })

	// Probe намеренно игнорирует ctx и висит на никогда не закрываемом
	// канале — handler всё равно обязан ответить по таймауту.
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	hungProbe := func(context.Context) error {
		<-block
		return nil
	}

	start := time.Now()
	rec := doRequest(t, Handler(Check{Name: "postgres", Probe: hungProbe}))
	elapsed := time.Since(start)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := decodeBody(t, rec)
	if len(body.Failed) != 1 || body.Failed[0] != "postgres" {
		t.Fatalf("ready body failed = %v, want [postgres]", body.Failed)
	}
	if elapsed > time.Second {
		t.Fatalf("handler took %v, want timeout around %v", elapsed, probeTimeout)
	}
}
