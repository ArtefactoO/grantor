package postgres

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func authFrame(code uint32, tail string) []byte {
	b := make([]byte, 9+len(tail))
	b[0] = 'R'
	binary.BigEndian.PutUint32(b[1:5], uint32(len(b)-1))
	binary.BigEndian.PutUint32(b[5:9], code)
	copy(b[9:], tail)
	return b
}

func TestPasswordAuthenticationBeforeConnectDenial(t *testing.T) {
	denied := &pgconn.PgError{Code: "42501", Routine: "CheckMyDatabase"}
	for _, tc := range []struct {
		name     string
		frames   []byte
		err      error
		accepted bool
	}{
		{"scram", append(authFrame(10, "SCRAM-SHA-256\x00"), authFrame(0, "")...), denied, true},
		{"md5", append(authFrame(5, "salt"), authFrame(0, "")...), denied, true},
		{"password", append(authFrame(3, ""), authFrame(0, "")...), denied, true},
		{"trust", authFrame(0, ""), denied, false},
		{"no auth ok", authFrame(10, "SCRAM-SHA-256\x00"), denied, false},
		{"arbitrary permission error", append(authFrame(10, ""), authFrame(0, "")...), &pgconn.PgError{Code: "42501", Routine: "other"}, false},
		{"hba rejection", append(authFrame(10, ""), authFrame(0, "")...), &pgconn.PgError{Code: "28000", Routine: "ClientAuthentication"}, false},
		{"password rejection", authFrame(10, ""), &pgconn.PgError{Code: "28P01"}, false},
		{"protocol failure", append(authFrame(10, ""), authFrame(0, "")...), errors.New("invalid server proof"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for size := 1; size <= len(tc.frames); size++ {
				o := &authenticationObservation{}
				for pos := 0; pos < len(tc.frames); pos += size {
					end := min(pos+size, len(tc.frames))
					o.consume(tc.frames[pos:end])
				}
				if authenticatedWithoutConnect(o, tc.err) != tc.accepted {
					t.Fatalf("chunk=%d observation=%+v", size, o)
				}
			}
		})
	}
}

func TestAuthenticationObserverDoesNotRetainPayloadOrChangeStream(t *testing.T) {
	canary := "server-payload-canary"
	stream := append(authFrame(10, canary), authFrame(11, canary)...)
	stream = append(stream, authFrame(12, canary)...)
	stream = append(stream, authFrame(0, "")...)
	o := &authenticationObservation{}
	got, err := io.ReadAll(authenticationReader{Reader: bytes.NewReader(stream), observation: o})
	if err != nil || !bytes.Equal(got, stream) {
		t.Fatal("observer changed protocol bytes")
	}
	if bytes.Contains([]byte(fmt.Sprintf("%+v", o)), []byte(canary)) {
		t.Fatal("observer retained server payload")
	}
	if !o.authenticated {
		t.Fatal("valid authentication was not observed")
	}
	// Authentication-looking bytes inside another message are not messages.
	fake := authFrame(0, "")
	fake[0] = 'E'
	other := &authenticationObservation{}
	other.consume(fake)
	if other.authenticated {
		t.Fatal("non-authentication body was interpreted as auth success")
	}
	// A buffered AuthOK after the error is not evidence of completed auth.
	late := &authenticationObservation{}
	buffered := append(authFrame(10, ""), []byte{'E', 0, 0, 0, 4}...)
	late.consume(append(buffered, authFrame(0, "")...))
	if authenticatedWithoutConnect(late, &pgconn.PgError{Code: "42501", Routine: "CheckMyDatabase"}) {
		t.Fatal("auth after server error was accepted")
	}
}
