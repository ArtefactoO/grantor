// Package wire реализует транспорт этапа 1c для протокола execution connector:
// mTLS + length-prefixed фрейминг каноничных Envelope поверх stdlib
// crypto/tls (см. ADR-0002, ADR-0006 и docs/architecture.md, раздел 4.3).
//
// # Выбор транспорта (этап 1)
//
// ADR-0002 называет целевым транспортом ConnectRPC поверх mTLS. Для этапа 1
// (доказать transport + auth + исполнение подписанного задания end-to-end)
// достаточно stdlib crypto/tls и простого length-prefixed фрейминга JSON —
// это избегает proto/ConnectRPC-зависимости, сохраняя все инварианты
// безопасности: mTLS-аутентификацию по клиентскому сертификату, Envelope,
// подписанные Ed25519/HMAC, и version negotiation. Контракт задания и подписи
// (пакет internal/connector) транспортонезависим по замыслу, поэтому замена
// транспорта на ConnectRPC в будущем не затрагивает operation engine.
//
// TODO(later): замена транспорта на ConnectRPC поверх mTLS (целевой транспорт
// ADR-0002). Контракт задания/подписи (Envelope/CanonicalBytes) при этом не
// меняется — переключается только фрейминг.
//
// # Формат кадра
//
// Каждый кадр: 1 байт тип + 4 байта длина payload (big-endian uint32) +
// payload. Payload кадров Hello/HelloAck/Job/Result/Error/Credentials —
// компактный JSON соответствующего типа. Длина ограничена MaxFrameSize,
// чтобы порченый или враждебный пир не заставил выделить произвольную
// память.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize — верхняя граница длины payload одного кадра. Snapshot
// discovery большого кластера умещается в этот предел с запасом; больший кадр
// трактуется как ошибка протокола.
const MaxFrameSize = 32 << 20 // 32 MiB

// headerSize — размер заголовка кадра: 1 байт тип + 4 байта длины.
const headerSize = 5

// Type — тип кадра транспорта. Значения фиксированы протоколом v1.
type Type uint8

const (
	// TypeHello — приветствие connector с версией протокола и capabilities.
	TypeHello Type = 1
	// TypeHelloAck — подтверждение gateway после успешной version
	// negotiation.
	TypeHelloAck Type = 2
	// TypeJob — подписанный Envelope (задание), gateway -> connector.
	TypeJob Type = 3
	// TypeResult — JobResult исполнения задания, connector -> gateway.
	TypeResult Type = 4
	// TypeError — ошибка уровня протокола/handshake (например, отказ version
	// negotiation); payload — JSON ErrorFrame.
	TypeError Type = 5
	// TypePing — heartbeat connector -> gateway (этап 3): пустой payload,
	// подтверждает живость соединения между заданиями. Gateway обновляет
	// last-seen по ЛЮБОМУ входящему кадру, поэтому ответный pong не нужен.
	// Обратная совместимость в пределах v1: обе стороны игнорируют кадры
	// неизвестных типов, не разрывая соединение, поэтому добавление типа
	// кадра не требует повышения ProtocolVersion (handshake негоциирует
	// версию, а liveness-политику задаёт конфигурация gateway).
	TypePing Type = 6
	// TypeCredentials — секретный материал задания (ADR-0014), gateway ->
	// connector: JSON connector.CredentialsFrame, привязанный к заданию по
	// JobID/Nonce. Отправляется СРАЗУ после кадра TypeJob того же задания
	// (оба кадра пишутся под одним мьютексом, поэтому смежны в потоке).
	// Единственный кадр протокола с секретами: не логируется, не
	// персистится, живёт только в mTLS-канале и памяти процессов; agent
	// зануляет материал после исполнения задания. Добавлен как
	// v1-совместимое расширение (см. TypePing о правиле «неизвестные кадры
	// игнорируются»): connector прежней сборки, не знающий этого кадра,
	// отвечает на задание нового контракта типизированным failed-результатом
	// (в payload больше нет Vault-ссылок, дереференсить нечего), поэтому
	// повышения ProtocolVersion не требуется.
	TypeCredentials Type = 7
)

// String возвращает читаемое имя типа кадра для логов.
func (t Type) String() string {
	switch t {
	case TypeHello:
		return "hello"
	case TypeHelloAck:
		return "hello_ack"
	case TypeJob:
		return "job"
	case TypeResult:
		return "result"
	case TypeError:
		return "error"
	case TypePing:
		return "ping"
	case TypeCredentials:
		return "credentials"
	default:
		return fmt.Sprintf("type(%d)", uint8(t))
	}
}

// HelloAck — тело кадра TypeHelloAck: версия протокола, на которой gateway
// принял connector. Совпадение версий уже проверено на handshake.
type HelloAck struct {
	ProtocolVersion string `json:"protocol_version"`
	SessionID       string `json:"session_id,omitempty"`
}

// ErrorFrame — тело кадра TypeError: очищенная причина отказа уровня
// протокола. Секретов не содержит (раздел 24).
type ErrorFrame struct {
	Reason string `json:"reason"`
}

// ErrFrameTooLarge возвращается, когда объявленная длина кадра превышает
// MaxFrameSize.
var ErrFrameTooLarge = errors.New("wire: frame exceeds max size")

// WriteFrame пишет один кадр: заголовок (тип+длина) и payload. Короткая
// запись возвращается как ошибка io.Writer.
func WriteFrame(w io.Writer, t Type, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), MaxFrameSize)
	}
	var header [headerSize]byte
	header[0] = byte(t)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("wire: write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("wire: write frame payload: %w", err)
	}
	return nil
}

// ReadFrame читает один кадр целиком и возвращает его тип и payload. Длина
// сверх MaxFrameSize отклоняется до чтения тела (ErrFrameTooLarge).
func ReadFrame(r io.Reader) (Type, []byte, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, fmt.Errorf("wire: read frame header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > MaxFrameSize {
		return 0, nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, MaxFrameSize)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("wire: read frame payload: %w", err)
	}
	return Type(header[0]), payload, nil
}

// WriteJSON сериализует v в компактный JSON и пишет его кадром типа t.
func WriteJSON(w io.Writer, t Type, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("wire: marshal %s frame: %w", t, err)
	}
	return WriteFrame(w, t, payload)
}

// ReadJSON читает кадр и, если его тип совпадает с want, разбирает payload в
// dst. Кадр TypeError преобразуется в ошибку с его причиной. Неожиданный тип —
// ошибка протокола.
func ReadJSON(r io.Reader, want Type, dst any) error {
	got, payload, err := ReadFrame(r)
	if err != nil {
		return err
	}
	if got == TypeError && want != TypeError {
		var ef ErrorFrame
		if e := json.Unmarshal(payload, &ef); e != nil {
			return fmt.Errorf("wire: read error frame: %w", e)
		}
		return fmt.Errorf("wire: peer returned error: %s", ef.Reason)
	}
	if got != want {
		return fmt.Errorf("wire: unexpected frame type %s, want %s", got, want)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("wire: unmarshal %s frame: %w", want, err)
	}
	return nil
}
