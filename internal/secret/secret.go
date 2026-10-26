// Package secret содержит редактирующую обёртку для секретных значений в
// памяти: паролей, tokens и private keys (docs/architecture.md, разделы 17
// и 24). Обёртка гарантирует, что секрет не попадает в логи, ошибки и
// сериализацию: fmt (все verbs, включая %s/%v/%+v/%#v/%d/%x), encoding/json,
// текстовая сериализация и log/slog выводят "[REDACTED]".
//
// Ограничения модели безопасности:
//
//   - Единственный способ получить секрет — Reveal или RevealString.
//     Вызывающий отвечает за раскрытые байты: они не должны попадать в логи,
//     ошибки, audit и metadata database, а после использования их стоит
//     занулить.
//   - Обёртка не защищает от прямого доступа к внутреннему буферу через
//     reflect или unsafe. Value передаётся только по значению и не
//     разыменовывается: код не должен извлекать внутренний слайс в обход
//     Reveal и не должен форматировать результат Reveal напрямую.
//   - Копии Value разделяют внутренний буфер, поэтому Wipe зануляет секрет
//     во всех копиях сразу.
package secret

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// redacted — текст, подставляемый вместо секрета во всех представлениях.
const redacted = "[REDACTED]"

// Value — секретное значение в памяти. Нулевое значение пригодно к
// использованию и означает отсутствие секрета.
type Value struct {
	b []byte
}

// Проверки соответствия интерфейсам редактирования на этапе компиляции.
var (
	_ fmt.Stringer           = Value{}
	_ fmt.GoStringer         = Value{}
	_ fmt.Formatter          = Value{}
	_ json.Marshaler         = Value{}
	_ encoding.TextMarshaler = Value{}
	_ slog.LogValuer         = Value{}
)

// New возвращает Value с копией b: последующие изменения исходного слайса не
// влияют на секрет.
func New(b []byte) Value {
	if len(b) == 0 {
		return Value{}
	}
	c := make([]byte, len(b))
	copy(c, b)
	return Value{b: c}
}

// FromString возвращает Value с копией содержимого s.
func FromString(s string) Value {
	return New([]byte(s))
}

// Reveal возвращает копию секретного значения. Это единственный способ
// (вместе с RevealString) получить секрет; вызывающий отвечает за то, чтобы
// раскрытые байты не утекли в логи и ошибки.
func (v Value) Reveal() []byte {
	if len(v.b) == 0 {
		return nil
	}
	c := make([]byte, len(v.b))
	copy(c, v.b)
	return c
}

// RevealString возвращает секретное значение строкой. См. Reveal.
func (v Value) RevealString() string {
	return string(v.b)
}

// IsZero сообщает, что секрет пуст или отсутствует.
func (v Value) IsZero() bool {
	return len(v.b) == 0
}

// Wipe зануляет внутренний буфер и освобождает его. Так как копии Value
// разделяют буфер, Wipe стирает секрет и во всех копиях.
func (v *Value) Wipe() {
	clear(v.b)
	v.b = nil
}

// String реализует fmt.Stringer и не раскрывает секрет.
func (v Value) String() string {
	return redacted
}

// GoString реализует fmt.GoStringer (%#v) и не раскрывает секрет.
func (v Value) GoString() string {
	return redacted
}

// Format реализует fmt.Formatter: любые verbs (%s, %v, %+v, %#v, %d, %x,
// %q и прочие) выводят redacted-заглушку вместо секрета.
func (v Value) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redacted)
}

// MarshalJSON реализует json.Marshaler и не раскрывает секрет.
func (v Value) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

// MarshalText реализует encoding.TextMarshaler и не раскрывает секрет.
func (v Value) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}

// LogValue реализует slog.LogValuer и не раскрывает секрет.
func (v Value) LogValue() slog.Value {
	return slog.StringValue(redacted)
}
