package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/secret"
)

// authentikStub — заглушка API Authentik: отдаёт заранее заданных
// пользователей, отфильтрованных так же, как это делает настоящий сервер, и
// записывает параметры последнего запроса для проверки того, что провайдер
// сузил выборку на стороне каталога, а не в памяти.
type authentikStub struct {
	users []authentikUser
	// lastQuery — параметры последнего запроса.
	lastQuery url.Values
	// authHeader — заголовок Authorization последнего запроса.
	authHeader string
	// status — код ответа; 0 = 200.
	status int
	// body — тело ответа вместо сгенерированного; пустое = обычный ответ.
	body string
}

func (s *authentikStub) handler(w http.ResponseWriter, r *http.Request) {
	s.lastQuery = r.URL.Query()
	s.authHeader = r.Header.Get("Authorization")

	if s.status != 0 {
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
		return
	}

	out := make([]authentikUser, 0, len(s.users))
	for _, u := range s.users {
		if want := s.lastQuery.Get("username"); want != "" && u.Username != want {
			continue
		}
		if q := s.lastQuery.Get("search"); q != "" &&
			!strings.Contains(strings.ToLower(u.Username+" "+u.Name), strings.ToLower(q)) {
			continue
		}
		out = append(out, u)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authentikUserPage{Results: out})
}

func newAuthentikTestProvider(t *testing.T, stub *authentikStub, group string) *AuthentikProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(stub.handler))
	t.Cleanup(srv.Close)

	provider, err := NewAuthentik(AuthentikConfig{
		BaseURL: srv.URL,
		Token:   secret.FromString("test-token"),
		Group:   group,
	})
	if err != nil {
		t.Fatalf("NewAuthentik: %v", err)
	}
	return provider
}

func TestNewAuthentikValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  AuthentikConfig
	}{
		{
			name: "empty base url",
			cfg:  AuthentikConfig{Token: secret.FromString("t")},
		},
		{
			name: "non http scheme",
			cfg:  AuthentikConfig{BaseURL: "ldaps://atk.example.com", Token: secret.FromString("t")},
		},
		{
			name: "url without host",
			cfg:  AuthentikConfig{BaseURL: "https://", Token: secret.FromString("t")},
		},
		{
			name: "empty token",
			cfg:  AuthentikConfig{BaseURL: "https://atk.example.com"},
		},
		{
			name: "broken ca pem",
			cfg: AuthentikConfig{
				BaseURL:   "https://atk.example.com",
				Token:     secret.FromString("t"),
				CACertPEM: []byte("not a certificate"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAuthentik(tc.cfg); err == nil {
				t.Fatal("NewAuthentik: want error, got nil")
			}
		})
	}
}

func TestAuthentikStatuses(t *testing.T) {
	stub := &authentikStub{users: []authentikUser{
		{Username: "alice", Name: "Alice", IsActive: true},
		{Username: "bob", Name: "Bob", IsActive: false},
	}}
	provider := newAuthentikTestProvider(t, stub, "")

	got, err := provider.Statuses(context.Background(), []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	want := map[string]Status{
		"alice": StatusActive,
		"bob":   StatusDisabled,
		// Контракт Provider: неизвестный каталогу субъект — это missing, а
		// не ошибка.
		"carol": StatusMissing,
	}
	for subject, wantStatus := range want {
		if got[subject] != wantStatus {
			t.Errorf("Statuses[%q] = %q, want %q", subject, got[subject], wantStatus)
		}
	}
	if len(got) != len(want) {
		t.Errorf("Statuses returned %d entries, want %d", len(got), len(want))
	}
	if v := stub.lastQuery.Get("username"); v == "" {
		t.Error("Statuses must filter by username on the server, got no username parameter")
	}
	if stub.authHeader != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want bearer token", stub.authHeader)
	}
}

// Точный фильтр username проверяется ещё раз на стороне grantor: ослабь
// каталог семантику фильтра — и чужая запись выдала бы уволенного за
// активного, то есть отменила бы offboarding-детекцию.
func TestAuthentikStatusesRejectsForeignMatch(t *testing.T) {
	stub := &authentikStub{users: []authentikUser{{Username: "alice.smith", Name: "Alice", IsActive: true}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Сервер, игнорирующий фильтр: отдаёт постороннюю запись.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authentikUserPage{Results: stub.users})
	}))
	t.Cleanup(srv.Close)

	provider, err := NewAuthentik(AuthentikConfig{BaseURL: srv.URL, Token: secret.FromString("t")})
	if err != nil {
		t.Fatalf("NewAuthentik: %v", err)
	}
	got, err := provider.Statuses(context.Background(), []string{"alice"})
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if got["alice"] != StatusMissing {
		t.Errorf("Statuses[alice] = %q, want %q for a foreign match", got["alice"], StatusMissing)
	}
}

func TestAuthentikStatusesEmptySubjects(t *testing.T) {
	stub := &authentikStub{}
	provider := newAuthentikTestProvider(t, stub, "")

	got, err := provider.Statuses(context.Background(), nil)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Statuses(nil) = %v, want empty", got)
	}
	if stub.lastQuery != nil {
		t.Error("Statuses(nil) must not call the directory")
	}
}

// Отказ каталога обязан оставаться ошибкой: превратись он в пустой
// результат — все принципалы разом оказались бы missing.
func TestAuthentikStatusesDirectoryFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		stub := &authentikStub{status: status, body: `{"detail":"nope"}`}
		provider := newAuthentikTestProvider(t, stub, "")

		_, err := provider.Statuses(context.Background(), []string{"alice"})
		if err == nil {
			t.Fatalf("Statuses with http %d: want error, got nil", status)
		}
		if strings.Contains(err.Error(), "test-token") {
			t.Fatalf("error text leaks the api token: %v", err)
		}
	}
}

func TestAuthentikSearch(t *testing.T) {
	stub := &authentikStub{users: []authentikUser{
		{Username: "alice", Name: "Alice Smith", IsActive: true},
		{Username: "bob", Name: "Bob Jones", IsActive: false},
	}}
	provider := newAuthentikTestProvider(t, stub, "")

	entries, err := provider.Search(context.Background(), "ali", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Search returned %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].Subject != "alice" || entries[0].DisplayName != "Alice Smith" {
		t.Errorf("Search entry = %+v, want subject alice with display name", entries[0])
	}
	if entries[0].Status != StatusActive {
		t.Errorf("Search entry status = %q, want %q", entries[0].Status, StatusActive)
	}
	if got := stub.lastQuery.Get("page_size"); got != "10" {
		t.Errorf("page_size = %q, want the limit passed to Search", got)
	}
	// Ограничение выдачи должно происходить на стороне каталога: иначе
	// перечисление организации на десятки тысяч человек тянется в память.
	if got := stub.lastQuery["type"]; len(got) != len(authentikPersonTypes) {
		t.Errorf("type filter = %v, want %v", got, authentikPersonTypes)
	}
}

// Выключенные записи возвращаются со StatusDisabled, а не скрываются:
// решение, заводить ли их, принимает вызывающий (контракт Searcher).
func TestAuthentikSearchKeepsDisabled(t *testing.T) {
	stub := &authentikStub{users: []authentikUser{{Username: "bob", Name: "Bob", IsActive: false}}}
	provider := newAuthentikTestProvider(t, stub, "")

	entries, err := provider.Search(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 1 || entries[0].Status != StatusDisabled {
		t.Fatalf("Search = %+v, want a single disabled entry", entries)
	}
	if stub.lastQuery.Has("search") {
		t.Error("empty query must enumerate the directory, not search for an empty string")
	}
}

func TestAuthentikSearchRequiresLimit(t *testing.T) {
	stub := &authentikStub{}
	provider := newAuthentikTestProvider(t, stub, "")

	if _, err := provider.Search(context.Background(), "", 0); err == nil {
		t.Fatal("Search with zero limit: want error, got nil")
	}
}

// Группа сужает только перечисление. На Statuses она не действует
// намеренно: иначе исключение человека из группы читалось бы как удаление
// из каталога и запускало бы offboarding по изменению прав.
func TestAuthentikGroupScopesSearchOnly(t *testing.T) {
	stub := &authentikStub{users: []authentikUser{{Username: "alice", Name: "Alice", IsActive: true}}}
	provider := newAuthentikTestProvider(t, stub, "grpGrantorAdmins")

	if _, err := provider.Search(context.Background(), "", 10); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := stub.lastQuery.Get("groups_by_name"); got != "grpGrantorAdmins" {
		t.Errorf("Search groups_by_name = %q, want the configured group", got)
	}

	if _, err := provider.Statuses(context.Background(), []string{"alice"}); err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if stub.lastQuery.Has("groups_by_name") {
		t.Error("Statuses must not scope by group: leaving a group is not leaving the directory")
	}
}
