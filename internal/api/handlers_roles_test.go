package api

import "testing"

// Валидация имени роли: имя уходит в CREATE ROLE как идентификатор, поэтому
// мусор отсекается до постановки операции, а не SQLSTATE из worker.
func TestCreateRoleRequestValidate(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "обычное имя", input: "app_read", want: "app_read"},
		{name: "пробелы по краям срезаются", input: "  app_read  ", want: "app_read"},
		{name: "пустое", input: "   ", wantErr: true},
		{name: "внутренний пробел", input: "app read", wantErr: true},
		{name: "перевод строки", input: "app\nread", wantErr: true},
		{name: "NUL", input: "app\x00read", wantErr: true},
		{name: "длиннее NAMEDATALEN", input: string(make([]byte, 64)), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := createRoleRequest{Name: tc.input}
			err := req.validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validate(%q) = nil, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate(%q): %v", tc.input, err)
			}
			if req.Name != tc.want {
				t.Errorf("normalized name = %q, want %q", req.Name, tc.want)
			}
		})
	}
}
