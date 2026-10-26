package adapter

import (
	"errors"
	"strings"
	"testing"
)

func TestInsufficientPrivilegeErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		err  *InsufficientPrivilegeError
		want []string // подстроки, которые обязаны присутствовать
		deny []string // подстроки, которых быть не должно
	}{
		{
			name: "with admin and detail",
			err: &InsufficientPrivilegeError{
				Engine:  "postgres",
				Admin:   "grantor_admin",
				Missing: "CREATEROLE (or SUPERUSER)",
				Detail:  "grant it with ALTER ROLE",
			},
			want: []string{`admin "grantor_admin"`, "CREATEROLE (or SUPERUSER)", "grant it with ALTER ROLE"},
		},
		{
			name: "without admin name",
			err: &InsufficientPrivilegeError{
				Engine:  "mongodb",
				Missing: "user-management privileges",
			},
			want: []string{"admin lacks", "user-management privileges"},
			deny: []string{`""`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("message %q does not contain %q", msg, w)
				}
			}
			for _, d := range tt.deny {
				if strings.Contains(msg, d) {
					t.Errorf("message %q must not contain %q", msg, d)
				}
			}
		})
	}
}

func TestInsufficientPrivilegeErrorIs(t *testing.T) {
	err := error(&InsufficientPrivilegeError{Engine: "mysql", Missing: "GRANT OPTION"})
	if !errors.Is(err, ErrInsufficientAdminPrivilege) {
		t.Error("errors.Is must match ErrInsufficientAdminPrivilege")
	}

	var target *InsufficientPrivilegeError
	if !errors.As(err, &target) {
		t.Fatal("errors.As must extract *InsufficientPrivilegeError")
	}
	if target.Engine != "mysql" {
		t.Errorf("extracted engine = %q, want mysql", target.Engine)
	}
}
