package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ArtefactoO/grantor/internal/secret"
)

func TestAuthentikAPIIdentityUsesImmutableUIDAndExactUsername(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       APIIdentity
		wantErr    bool
	}{
		{"active", `{"results":[{"pk":7,"uid":"immutable","username":"alice","email":"alice@example.test","is_active":true,"groups_obj":[{"name":"grantor-operators"}]}]}`,
			APIIdentity{UID: "immutable", Username: "alice", Email: "alice@example.test", Status: StatusActive, Groups: []string{"grantor-operators"}}, false},
		{"disabled", `{"results":[{"uid":"immutable","username":"alice","email":"alice@example.test","is_active":false,"groups_obj":[]}]}`,
			APIIdentity{UID: "immutable", Username: "alice", Email: "alice@example.test", Status: StatusDisabled, Groups: []string{}}, false},
		{"different username", `{"results":[{"uid":"other","username":"bob","email":"bob@example.test","is_active":true}]}`,
			APIIdentity{Username: "alice", Status: StatusMissing}, false},
		{"pk is not uid", `{"results":[{"pk":7,"username":"alice","email":"alice@example.test","is_active":true}]}`, APIIdentity{}, true},
		{"ambiguous", `{"results":[{"uid":"one","username":"alice","email":"a@e.test"},{"uid":"two","username":"alice","email":"b@e.test"}]}`, APIIdentity{}, true},
		{"bad group", `{"results":[{"uid":"one","username":"alice","email":"a@e.test","groups_obj":[{}]}]}`, APIIdentity{}, true},
		{"missing groups", `{"results":[{"uid":"one","username":"alice","email":"a@e.test","is_active":true}]}`, APIIdentity{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("username") != "alice" || r.URL.Query().Has("groups_by_name") {
					t.Error("identity lookup changed membership scope")
				}
				w.Header().Set("Content-Type", "application/json")
				var body any
				if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
					t.Fatal(err)
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			provider, err := NewAuthentik(AuthentikConfig{BaseURL: srv.URL, Token: secret.FromString("fixture-token"), Group: "import-only-group"})
			if err != nil {
				t.Fatal(err)
			}
			got, err := provider.APIIdentity(context.Background(), "alice")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}
