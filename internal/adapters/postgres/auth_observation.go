package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Observe server authentication codes only, after pgx's TLS transport. No client
// traffic, password, SASL payload, error body or database data is retained.
type authenticationObservation struct {
	header                                    [5]byte
	headerN                                   int
	remaining                                 uint32
	code                                      [4]byte
	codeN                                     int
	password, authenticated, invalid, stopped bool
	authenticationOK, unsupported             bool
}

func (o *authenticationObservation) consume(data []byte) {
	if o.invalid || o.stopped {
		return
	}
	for _, b := range data {
		if o.headerN < len(o.header) {
			o.header[o.headerN] = b
			o.headerN++
			if o.headerN < len(o.header) {
				continue
			}
			size := binary.BigEndian.Uint32(o.header[1:])
			if size < 4 || size > 16*1024*1024 {
				o.invalid = true
				return
			}
			// Read may coalesce multiple messages. Authentication after an
			// ErrorResponse was never processed by pgx and must not count.
			if o.header[0] == 'E' {
				o.stopped = true
				return
			}
			o.remaining = size - 4
			o.codeN = 0
			if o.remaining == 0 {
				o.finish()
			}
			continue
		}
		if o.header[0] == 'R' && o.codeN < len(o.code) {
			o.code[o.codeN] = b
			o.codeN++
		}
		o.remaining--
		if o.remaining == 0 {
			o.finish()
		}
	}
}

func (o *authenticationObservation) finish() {
	if o.header[0] == 'R' {
		if o.codeN != 4 {
			o.invalid = true
		} else {
			switch binary.BigEndian.Uint32(o.code[:]) {
			case 3, 5, 10:
				o.password = true
			case 0:
				o.authenticationOK = true
				o.authenticated = o.password && !o.invalid
			case 11, 12: // SASL continuation/final; pgx validates the server signature.
			default:
				o.unsupported = true
				o.invalid = true
			}
		}
	}
	o.headerN = 0
}

type authenticationReader struct {
	io.Reader
	observation *authenticationObservation
}

func (r authenticationReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.observation.consume(p[:n])
	return n, err
}

func (a *Adapter) connectForCredentialProof(ctx context.Context, cfg adapter.Connection, database string) (*pgx.Conn, *authenticationObservation, error) {
	o := &authenticationObservation{}
	cc, err := connConfigWithDialer(cfg, database, a.dialContext)
	if err != nil {
		return nil, o, err
	}
	build := cc.BuildFrontend
	cc.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		// A DNS/fallback retry must not reuse authentication from another socket.
		*o = authenticationObservation{}
		return build(authenticationReader{Reader: r, observation: o}, w)
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	return conn, o, err
}

// PostgreSQL authenticates before CheckMyDatabase checks CONNECT. Accept only
// that specific post-authentication denial, not arbitrary 42501 or HBA errors.
func authenticatedWithoutConnect(o *authenticationObservation, err error) bool {
	var pgErr *pgconn.PgError
	return o.passwordAuthenticated() && errors.As(err, &pgErr) &&
		pgErr.Code == "42501" && pgErr.Routine == "CheckMyDatabase"
}

func (o *authenticationObservation) passwordAuthenticated() bool {
	return o != nil && o.password && o.authenticated && !o.invalid
}
