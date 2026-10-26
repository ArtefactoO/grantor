package yopass

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{PublicURL: "http://localhost:58090"}); err == nil {
		t.Error("New without api url: err = nil, want error")
	}
	if _, err := New(Config{APIURL: "http://yopass:1337"}); err == nil {
		t.Error("New without public url: err = nil, want error")
	}
	c, err := New(Config{APIURL: "http://yopass:1337/", PublicURL: "http://localhost:58090/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.apiURL != "http://yopass:1337" || c.publicURL != "http://localhost:58090" {
		t.Errorf("urls not normalized: api=%q public=%q", c.apiURL, c.publicURL)
	}
}

func TestShareInvalidTTL(t *testing.T) {
	// Сервер не поднимается: невалидный TTL обязан отсекаться до любого
	// сетевого вызова.
	c, err := New(Config{APIURL: "http://127.0.0.1:1", PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Share(t.Context(), []byte("secret"), 60, true); err == nil {
		t.Error("Share with unsupported ttl: err = nil, want error")
	}
	if _, err := c.Share(t.Context(), nil, 3600, true); err == nil {
		t.Error("Share with empty message: err = nil, want error")
	}
}

func TestShareEncryptsAndBuildsLink(t *testing.T) {
	const plaintext = "username: svc\npassword: super-secret-value"
	const secretID = "0123456789ABCDEFGHIJKL"

	var got storeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/create/secret" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("unmarshal request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(storeResponse{Message: secretID}); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()

	c, err := New(Config{APIURL: srv.URL, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	link, err := c.Share(t.Context(), []byte(plaintext), 86400, true)
	if err != nil {
		t.Fatalf("Share: %v", err)
	}

	if got.Expiration != 86400 {
		t.Errorf("expiration = %d, want 86400", got.Expiration)
	}
	if !got.OneTime {
		t.Error("one_time = false, want true")
	}
	// На сервер уходит только PGP-шифртекст, не plaintext.
	if !strings.Contains(got.Message, "-----BEGIN PGP MESSAGE-----") {
		t.Errorf("message is not an armored PGP ciphertext: %q", got.Message)
	}
	if strings.Contains(got.Message, "super-secret-value") {
		t.Error("plaintext leaked into stored message")
	}

	prefix := "http://localhost:58090/#/s/" + secretID + "/"
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("link = %q, want prefix %q", link, prefix)
	}
	if key := strings.TrimPrefix(link, prefix); key == "" {
		t.Error("link has empty decryption key fragment")
	}
}

func TestShareServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"secret content echo"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c, err := New(Config{APIURL: srv.URL, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Share(t.Context(), []byte("secret"), 3600, true)
	if err == nil {
		t.Fatal("Share on server error: err = nil, want error")
	}
	// Тело ответа сервера в ошибку не попадает.
	if strings.Contains(err.Error(), "echo") {
		t.Errorf("error leaks server response body: %v", err)
	}
}

// flavorServer — фейковый Yopass с настраиваемым поколением API: считает
// запросы по путям, чтобы проверить fallback и кеширование решения.
type flavorServer struct {
	modernOK     bool
	legacyOK     bool
	modernStatus int // ответ на /create/secret, когда modernOK=false

	mu         sync.Mutex
	modernHits int
	legacyHits int
}

func (f *flavorServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/create/secret":
			f.mu.Lock()
			f.modernHits++
			f.mu.Unlock()
			if !f.modernOK {
				status := f.modernStatus
				if status == 0 {
					status = http.StatusNotFound
				}
				http.Error(w, `{"message":"Not found"}`, status)
				return
			}
		case "/secret":
			f.mu.Lock()
			f.legacyHits++
			f.mu.Unlock()
			if !f.legacyOK {
				http.NotFound(w, r)
				return
			}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(storeResponse{Message: "0123456789ABCDEFGHIJKL"}); err != nil {
			t.Errorf("write response: %v", err)
		}
	}
}

func (f *flavorServer) hits() (modern, legacy int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.modernHits, f.legacyHits
}

// shareTwice выполняет два Share подряд (проверка кеширования решения о
// пути между вызовами).
func shareTwice(t *testing.T, c *Client) {
	t.Helper()
	for i := range 2 {
		if _, err := c.Share(t.Context(), []byte("secret"), 3600, true); err != nil {
			t.Fatalf("Share #%d: %v", i+1, err)
		}
	}
}

// TestStorePathModernOnly — новое поколение API (bundled dev-Yopass):
// используется только /create/secret, классический путь не трогается, после
// первого успеха решение закешировано.
func TestStorePathModernOnly(t *testing.T) {
	fs := &flavorServer{modernOK: true}
	srv := httptest.NewServer(fs.handler(t))
	defer srv.Close()

	c, err := New(Config{APIURL: srv.URL, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	shareTwice(t, c)
	modern, legacy := fs.hits()
	if modern != 2 || legacy != 0 {
		t.Errorf("hits = modern:%d legacy:%d, want modern:2 legacy:0", modern, legacy)
	}
}

// TestStorePathLegacyFallback — старое поколение API (общий инстанс
// организации): /create/secret отвечает 404, клиент повторяет запрос на
// классический /secret и кеширует решение — второй Share идёт сразу на
// /secret без повторной пробы (ровно один 404 за всё время жизни клиента).
func TestStorePathLegacyFallback(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fs := &flavorServer{legacyOK: true, modernStatus: status}
			srv := httptest.NewServer(fs.handler(t))
			defer srv.Close()

			c, err := New(Config{APIURL: srv.URL, PublicURL: "http://localhost:58090"})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			shareTwice(t, c)
			modern, legacy := fs.hits()
			if modern != 1 || legacy != 2 {
				t.Errorf("hits = modern:%d legacy:%d, want modern:1 legacy:2 (decision must be cached)",
					modern, legacy)
			}
		})
	}
}

// TestStorePathBothSupported — сервер, знающий оба пути: клиент остаётся на
// современном /create/secret и не делает лишних запросов.
func TestStorePathBothSupported(t *testing.T) {
	fs := &flavorServer{modernOK: true, legacyOK: true}
	srv := httptest.NewServer(fs.handler(t))
	defer srv.Close()

	c, err := New(Config{APIURL: srv.URL, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	shareTwice(t, c)
	modern, legacy := fs.hits()
	if modern != 2 || legacy != 0 {
		t.Errorf("hits = modern:%d legacy:%d, want modern:2 legacy:0", modern, legacy)
	}
}

// TestStorePathErrorHygiene — non-404 ошибка современного пути не приводит к
// fallback и не тащит тело ответа в текст ошибки.
func TestStorePathErrorHygiene(t *testing.T) {
	fs := &flavorServer{legacyOK: true, modernStatus: http.StatusBadRequest}
	srv := httptest.NewServer(fs.handler(t))
	defer srv.Close()

	c, err := New(Config{APIURL: srv.URL, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Share(t.Context(), []byte("secret"), 3600, true)
	if err == nil {
		t.Fatal("Share on 400: err = nil, want error")
	}
	if strings.Contains(err.Error(), "Not found") {
		t.Errorf("error leaks server response body: %v", err)
	}
	if _, legacy := fs.hits(); legacy != 0 {
		t.Errorf("legacy path was probed after a non-404 error (hits=%d), want 0", legacy)
	}
}
