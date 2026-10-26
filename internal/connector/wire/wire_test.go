package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"hello":"world"}`)
	if err := wire.WriteFrame(&buf, wire.TypeJob, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	typ, got, err := wire.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != wire.TypeJob {
		t.Errorf("type = %v, want %v", typ, wire.TypeJob)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
}

func TestFrameMultipleInStream(t *testing.T) {
	var buf bytes.Buffer
	frames := []struct {
		typ     wire.Type
		payload []byte
	}{
		{wire.TypeHello, []byte("a")},
		{wire.TypeHelloAck, []byte("")},
		{wire.TypeResult, []byte("ccc")},
	}
	for _, f := range frames {
		if err := wire.WriteFrame(&buf, f.typ, f.payload); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for i, want := range frames {
		typ, got, err := wire.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if typ != want.typ || !bytes.Equal(got, want.payload) {
			t.Errorf("frame[%d] = (%v,%q), want (%v,%q)", i, typ, got, want.typ, want.payload)
		}
	}
}

func TestReadFrameRejectsOversizeLength(t *testing.T) {
	// Заголовок объявляет длину сверх MaxFrameSize — тело не должно читаться.
	var header [5]byte
	header[0] = byte(wire.TypeJob)
	binary.BigEndian.PutUint32(header[1:], wire.MaxFrameSize+1)
	_, _, err := wire.ReadFrame(bytes.NewReader(header[:]))
	if !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("ReadFrame err = %v, want ErrFrameTooLarge", err)
	}
}

func TestWriteFrameRejectsOversizePayload(t *testing.T) {
	huge := make([]byte, wire.MaxFrameSize+1)
	if err := wire.WriteFrame(io.Discard, wire.TypeJob, huge); !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("WriteFrame err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameTruncated(t *testing.T) {
	var buf bytes.Buffer
	if err := wire.WriteFrame(&buf, wire.TypeJob, []byte("payload")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Обрезаем поток на середине тела.
	truncated := buf.Bytes()[:6]
	_, _, err := wire.ReadFrame(bytes.NewReader(truncated))
	if err == nil {
		t.Fatal("ReadFrame on truncated stream must fail")
	}
}

func TestReadJSONErrorFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := wire.WriteJSON(&buf, wire.TypeError, wire.ErrorFrame{Reason: "boom"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// Ждём HelloAck, а прилетает TypeError — он преобразуется в ошибку с причиной.
	var ack wire.HelloAck
	err := wire.ReadJSON(&buf, wire.TypeHelloAck, &ack)
	if err == nil {
		t.Fatal("ReadJSON must surface an error frame as error")
	}
	if got := err.Error(); got == "" || !bytes.Contains([]byte(got), []byte("boom")) {
		t.Errorf("error = %q, want it to mention the reason", got)
	}
}

func TestReadJSONUnexpectedType(t *testing.T) {
	var buf bytes.Buffer
	if err := wire.WriteJSON(&buf, wire.TypeResult, wire.HelloAck{ProtocolVersion: "v1"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(&buf, wire.TypeHelloAck, &ack); err == nil {
		t.Fatal("ReadJSON must reject unexpected frame type")
	}
}
