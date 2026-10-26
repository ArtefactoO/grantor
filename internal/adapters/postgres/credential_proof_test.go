package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCredentialProofDistinguishesPasswordFromDatabaseAdmission(t *testing.T) {
	for _, tc := range []struct {
		code             string
		password, denied bool
	}{
		{"28P01", true, false}, {"28000", false, true}, {"42501", false, true},
		{"3D000", false, true}, {"08006", false, false}, {"53300", false, false},
	} {
		err := fmt.Errorf("connect: %w", &pgconn.PgError{Code: tc.code})
		if isAuthenticationFailure(err) != tc.password || isProofDatabaseDenied(err) != tc.denied {
			t.Errorf("incorrect classification for %s", tc.code)
		}
	}
	if isAuthenticationFailure(errors.New("timeout")) || isProofDatabaseDenied(errors.New("timeout")) {
		t.Fatal("transport error became credential rejection")
	}
}
