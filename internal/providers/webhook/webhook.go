// Package webhook — generic исходящие уведомления control plane. Формат
// нейтральный (JSON POST): конкретный мессенджер подключается адаптером на
// стороне получателя (Mattermost/Telegram-мост, n8n и т.п.), grantor не
// знает о них ничего.
//
// Инвариант безопасности (раздел 24): в payload не попадают секреты и их
// производные — только несекретные метаданные операций.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultTimeout — HTTP timeout отправки; уведомление не стоит того, чтобы
// держать горутину дольше.
const DefaultTimeout = 10 * time.Second

// Event — одно уведомление. Type — машинное имя события
// (operation.pending_approval, operation.failed), Title — короткая
// человекочитаемая строка, Fields — несекретный контекст.
type Event struct {
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Fields     map[string]string `json:"fields,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// Client шлёт события на настроенный URL. Nil-клиент безопасен: Send —
// no-op, вызывающие не проверяют конфигурацию.
type Client struct {
	url  string
	http *http.Client
}

// New возвращает клиента; пустой url — nil (уведомления выключены).
func New(url string, timeout time.Duration) *Client {
	if url == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{url: url, http: &http.Client{Timeout: timeout}}
}

// Send отправляет событие. Ошибка возвращается вызывающему для
// логирования; уведомления best-effort и не должны валить основной поток.
func (c *Client) Send(ctx context.Context, event Event) error {
	if c == nil {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("webhook: marshal event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send %s: %w", event.Type, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: send %s: status %d", event.Type, resp.StatusCode)
	}
	return nil
}
