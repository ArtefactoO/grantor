package api

// Юнит-тесты content negotiation тела манифеста (decodeManifestBody):
// JSON по умолчанию, YAML по Content-Type, 400 на битые тела, 415 на
// неподдерживаемый Content-Type — и паритет yaml/json-тегов apply-запроса.

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/accessmanifest"
)

// manifestBodyJSON и manifestBodyYAML — один и тот же манифест в двух
// форматах; декодирование обязано давать одинаковые структуры.
const manifestBodyJSON = `{
  "version": "v1",
  "entries": [{"principal": "svc", "connection": "pg-main", "role": "role:ro"}],
  "confirm": true
}`

const manifestBodyYAML = `
version: v1
entries:
  - principal: svc
    connection: pg-main
    role: role:ro
confirm: true
`

// wantApplyRequest — ожидаемый результат декодирования обоих тел.
func wantApplyRequest() manifestApplyRequest {
	return manifestApplyRequest{
		Manifest: accessmanifest.Manifest{
			Version: accessmanifest.Version,
			Entries: []accessmanifest.Entry{
				{Principal: "svc", Connection: "pg-main", Role: "role:ro"},
			},
		},
		Confirm: true,
	}
}

func TestDecodeManifestBody(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        string
		wantOK      bool
		wantStatus  int
		wantDecoded bool
	}{
		{name: "json without content type", contentType: "", body: manifestBodyJSON, wantOK: true, wantDecoded: true},
		{name: "json content type", contentType: "application/json", body: manifestBodyJSON, wantOK: true, wantDecoded: true},
		{name: "json with charset", contentType: "application/json; charset=utf-8", body: manifestBodyJSON, wantOK: true, wantDecoded: true},
		{name: "yaml content type", contentType: "application/yaml", body: manifestBodyYAML, wantOK: true, wantDecoded: true},
		{name: "yaml text content type", contentType: "text/yaml", body: manifestBodyYAML, wantOK: true, wantDecoded: true},
		{name: "yaml with charset", contentType: "application/yaml; charset=utf-8", body: manifestBodyYAML, wantOK: true, wantDecoded: true},
		{name: "invalid json", contentType: "application/json", body: "{not json", wantStatus: http.StatusBadRequest},
		{name: "invalid yaml", contentType: "application/yaml", body: "entries: [::broken", wantStatus: http.StatusBadRequest},
		{name: "json body under yaml type is invalid mapping", contentType: "application/yaml", body: "\t{bad", wantStatus: http.StatusBadRequest},
		{name: "unsupported content type", contentType: "text/plain", body: manifestBodyYAML, wantStatus: http.StatusUnsupportedMediaType},
		{name: "unsupported xml", contentType: "application/xml", body: "<m/>", wantStatus: http.StatusUnsupportedMediaType},
		{name: "malformed content type", contentType: "application/", body: manifestBodyJSON, wantStatus: http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/access/apply", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			rec := httptest.NewRecorder()
			var dst manifestApplyRequest
			ok := decodeManifestBody(rec, req, &dst)
			if ok != tc.wantOK {
				t.Fatalf("decodeManifestBody() = %v, want %v (status %d, body %s)",
					ok, tc.wantOK, rec.Code, rec.Body.String())
			}
			if !tc.wantOK && rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantDecoded && !reflect.DeepEqual(dst, wantApplyRequest()) {
				t.Errorf("decoded = %+v, want %+v", dst, wantApplyRequest())
			}
		})
	}
}

// TestManifestApplyRequestTagParity закрепляет YAML-представление
// apply-запроса: встроенный Manifest поднимается на верхний уровень
// (yaml:",inline" — зеркало JSON-встраивания), а у остальных полей yaml-тег
// повторяет json-тег.
func TestManifestApplyRequestTagParity(t *testing.T) {
	typ := reflect.TypeOf(manifestApplyRequest{})
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Anonymous {
			if got := field.Tag.Get("yaml"); got != ",inline" {
				t.Errorf("embedded %s: yaml tag = %q, want \",inline\"", field.Name, got)
			}
			continue
		}
		jsonTag := field.Tag.Get("json")
		yamlTag := field.Tag.Get("yaml")
		if jsonTag == "" || jsonTag != yamlTag {
			t.Errorf("%s: yaml tag %q differs from json tag %q", field.Name, yamlTag, jsonTag)
		}
	}
}
