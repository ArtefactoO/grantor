// Package postgresconfig defines the non-secret per-connection PostgreSQL
// role-policy configuration shared by the API, connection projection and
// PostgreSQL adapter.
package postgresconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

const (
	// AttributeRolePolicyTemplates is the adapter.Connection.Attributes key.
	AttributeRolePolicyTemplates = "postgres_role_policy_templates"

	ProfileRead      = "read"
	ProfileReadWrite = "read_write"

	MaxTemplates         = 64
	MaxKeyLength         = 64
	MaxNameLength        = 128
	MaxDescriptionLength = 512
	MaxIdentifierLength  = 63
	MaxSchemas           = 64
	MaxOwnerRoles        = 64
	MaxCreatorRoles      = 64
)

var (
	templateKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	identifierRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// RolePolicyTemplate describes one dedicated NOLOGIN role. OwnerRoles limit
// current-object ACL management; CreatorRoles independently select the roles
// whose future-object default privileges are managed.
type RolePolicyTemplate struct {
	Key          string   `json:"key"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RoleName     string   `json:"role_name"`
	Database     string   `json:"database"`
	Schemas      []string `json:"schemas"`
	OwnerRoles   []string `json:"owner_roles"`
	CreatorRoles []string `json:"creator_roles"`
	Profile      string   `json:"profile"`
}

// Normalize returns a canonical copy used by fingerprints and adapter plans.
// Input order never changes the policy identity.
func Normalize(template RolePolicyTemplate) RolePolicyTemplate {
	out := template
	out.Schemas = sortedUnique(template.Schemas)
	out.OwnerRoles = sortedUnique(template.OwnerRoles)
	out.CreatorRoles = sortedUnique(template.CreatorRoles)
	return out
}

// Validate rejects ambiguous, unsafe or unbounded template configuration.
// PostgreSQL accepts quoted identifiers with almost arbitrary contents, but
// managed policy names intentionally use a small portable subset so the same
// identifiers can be validated independently in the control plane and the
// closed direct SQL statement builder.
func Validate(templates []RolePolicyTemplate) error {
	if len(templates) > MaxTemplates {
		return fmt.Errorf("postgres_role_policy_templates has %d entries; maximum is %d", len(templates), MaxTemplates)
	}
	keys := make(map[string]struct{}, len(templates))
	names := make(map[string]struct{}, len(templates))
	roles := make(map[string]struct{}, len(templates))
	for i, template := range templates {
		field := fmt.Sprintf("postgres_role_policy_templates[%d]", i)
		if err := validateText(field+".key", template.Key, MaxKeyLength); err != nil {
			return err
		}
		if !templateKeyRE.MatchString(template.Key) {
			return fmt.Errorf("%s.key must match %s", field, templateKeyRE.String())
		}
		if err := validateText(field+".name", template.Name, MaxNameLength); err != nil {
			return err
		}
		if err := validateText(field+".description", template.Description, MaxDescriptionLength); err != nil {
			return err
		}
		if err := validateIdentifier(field+".role_name", template.RoleName); err != nil {
			return err
		}
		if strings.HasPrefix(strings.ToLower(template.RoleName), "pg_") {
			return fmt.Errorf("%s.role_name uses the reserved pg_ prefix", field)
		}
		if err := validateIdentifier(field+".database", template.Database); err != nil {
			return err
		}
		if err := validateIdentifierList(field+".schemas", template.Schemas, MaxSchemas); err != nil {
			return err
		}
		for _, schema := range template.Schemas {
			lower := strings.ToLower(schema)
			if strings.HasPrefix(lower, "pg_") || lower == "information_schema" {
				return fmt.Errorf("%s.schemas contains reserved schema %q", field, schema)
			}
		}
		if err := validateIdentifierList(field+".owner_roles", template.OwnerRoles, MaxOwnerRoles); err != nil {
			return err
		}
		if slices.Contains(template.OwnerRoles, template.RoleName) {
			return fmt.Errorf("%s.owner_roles must not contain the policy role", field)
		}
		if err := validateIdentifierList(field+".creator_roles", template.CreatorRoles, MaxCreatorRoles); err != nil {
			return err
		}
		if slices.Contains(template.CreatorRoles, template.RoleName) {
			return fmt.Errorf("%s.creator_roles must not contain the policy role", field)
		}
		switch template.Profile {
		case ProfileRead, ProfileReadWrite:
		default:
			return fmt.Errorf("%s.profile %q is not supported", field, template.Profile)
		}
		if _, exists := keys[template.Key]; exists {
			return fmt.Errorf("postgres_role_policy_templates key %q is duplicated", template.Key)
		}
		if _, exists := names[template.Name]; exists {
			return fmt.Errorf("postgres_role_policy_templates name %q is duplicated", template.Name)
		}
		if _, exists := roles[template.RoleName]; exists {
			return fmt.Errorf("postgres_role_policy_templates role %q is managed by more than one template", template.RoleName)
		}
		keys[template.Key] = struct{}{}
		names[template.Name] = struct{}{}
		roles[template.RoleName] = struct{}{}
	}
	return nil
}

// Fingerprint returns a stable full SHA-256 fingerprint of the normalized
// template. It contains no secret material.
func Fingerprint(template RolePolicyTemplate) string {
	normalized := Normalize(template)
	raw, _ := json.Marshal(normalized)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CatalogFingerprint binds discovery-derived capabilities to the exact
// configured catalog, preventing a stale topology from authorizing a newly
// patched template before its own exact authority/scope snapshot has been observed.
func CatalogFingerprint(templates []RolePolicyTemplate) string {
	normalized := make([]RolePolicyTemplate, len(templates))
	for i := range templates {
		normalized[i] = Normalize(templates[i])
	}
	slices.SortFunc(normalized, func(a, b RolePolicyTemplate) int {
		return strings.Compare(a.Key, b.Key)
	})
	raw, _ := json.Marshal(normalized)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// FromAttributes restores typed templates after either a direct projection or
// a connector JSON round-trip (where map values decode as []any/map[string]any).
func FromAttributes(attributes map[string]any) ([]RolePolicyTemplate, error) {
	value, ok := attributes[AttributeRolePolicyTemplates]
	if !ok || value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", AttributeRolePolicyTemplates, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var templates []RolePolicyTemplate
	if err := dec.Decode(&templates); err != nil {
		return nil, fmt.Errorf("decode %s: %w", AttributeRolePolicyTemplates, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: trailing data", AttributeRolePolicyTemplates)
	}
	if err := Validate(templates); err != nil {
		return nil, err
	}
	for i := range templates {
		templates[i] = Normalize(templates[i])
	}
	return templates, nil
}

func validateText(field, value string, max int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have leading or trailing whitespace", field)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", field, max)
	}
	return nil
}

func validateIdentifier(field, value string) error {
	if err := validateText(field, value, MaxIdentifierLength); err != nil {
		return err
	}
	if !identifierRE.MatchString(value) {
		return fmt.Errorf("%s must match %s", field, identifierRE.String())
	}
	return nil
}

func validateIdentifierList(field string, values []string, max int) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(values) > max {
		return fmt.Errorf("%s has %d entries; maximum is %d", field, len(values), max)
	}
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		if err := validateIdentifier(fmt.Sprintf("%s[%d]", field, i), value); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicate identifier %q", field, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func sortedUnique(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}
