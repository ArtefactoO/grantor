package accessmanifest

// Тесты YAML-представления манифеста: паритет yaml/json-тегов (рефлексия —
// защита от дрейфа при добавлении полей), round-trip struct↔YAML и
// эквивалентность декодирования YAML и JSON одного документа.

import (
	"encoding/json"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestManifestTagParity рефлексией проверяет, что у каждого поля Manifest и
// Entry yaml-тег в точности повторяет json-тег (имя и опции вроде omitempty):
// оба формата обязаны декодироваться в одну структуру без расхождений.
func TestManifestTagParity(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(Manifest{}),
		reflect.TypeOf(Entry{}),
	} {
		for i := range typ.NumField() {
			field := typ.Field(i)
			jsonTag, jsonOK := field.Tag.Lookup("json")
			yamlTag, yamlOK := field.Tag.Lookup("yaml")
			if !jsonOK || !yamlOK {
				t.Errorf("%s.%s: json tag present=%v, yaml tag present=%v, want both",
					typ.Name(), field.Name, jsonOK, yamlOK)
				continue
			}
			if jsonTag != yamlTag {
				t.Errorf("%s.%s: yaml tag %q differs from json tag %q",
					typ.Name(), field.Name, yamlTag, jsonTag)
			}
		}
	}
}

// TestManifestYAMLRoundTrip проверяет, что манифест переживает
// сериализацию в YAML и обратно без потерь (включая omitempty-поля).
func TestManifestYAMLRoundTrip(t *testing.T) {
	src := Manifest{
		Version:     Version,
		Environment: "test",
		Prune:       true,
		Entries: []Entry{
			{Principal: "svc-a", Connection: "pg-main", Role: "role:ro"},
			{Principal: "svc-b", Connection: "pg-main", Role: "role:rw", State: string(StateAbsent)},
		},
	}
	data, err := yaml.Marshal(src)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	var got Manifest
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\nyaml:\n%s", err, data)
	}
	if !reflect.DeepEqual(got, src) {
		t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v\nyaml:\n%s", got, src, data)
	}
}

// TestManifestYAMLDecodesLikeJSON проверяет, что один и тот же манифест в
// YAML и в JSON декодируется в одинаковые структуры: YAML — только другая
// сериализация, не другая модель.
func TestManifestYAMLDecodesLikeJSON(t *testing.T) {
	const yamlDoc = `
version: v1
environment: test
prune: true
entries:
  - principal: svc-a
    connection: pg-main
    role: role:ro
  - principal: svc-b
    connection: pg-main
    role: role:rw
    state: absent
`
	const jsonDoc = `{
  "version": "v1",
  "environment": "test",
  "prune": true,
  "entries": [
    {"principal": "svc-a", "connection": "pg-main", "role": "role:ro"},
    {"principal": "svc-b", "connection": "pg-main", "role": "role:rw", "state": "absent"}
  ]
}`
	var fromYAML, fromJSON Manifest
	if err := yaml.Unmarshal([]byte(yamlDoc), &fromYAML); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if err := json.Unmarshal([]byte(jsonDoc), &fromJSON); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, fromJSON) {
		t.Errorf("decode mismatch:\nyaml %+v\njson %+v", fromYAML, fromJSON)
	}
	if err := fromYAML.Validate(); err != nil {
		t.Errorf("Validate() after YAML decode = %v, want nil", err)
	}
}
