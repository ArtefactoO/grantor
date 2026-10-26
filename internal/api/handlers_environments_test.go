package api

import "testing"

// Имя окружения становится сегментом Vault-пути общего секрета принципала,
// поэтому пробелы срезаются, а '/' и пустота отклоняются до записи в базу.
func TestCreateEnvironmentRequestValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain", "stage", "stage", false},
		{"trimmed", "  stage  ", "stage", false},
		{"empty", "", "", true},
		{"spaces only", "   ", "", true},
		{"slash", "stage/eu", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := createEnvironmentRequest{Name: tc.in}
			err := req.validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validate(%q): expected error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate(%q): %v", tc.in, err)
			}
			if req.Name != tc.want {
				t.Errorf("normalized name = %q, want %q", req.Name, tc.want)
			}
		})
	}
}
