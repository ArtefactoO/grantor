// Package rabbitmqconfig defines the non-secret per-connection configuration
// shared by the API, connection projection and RabbitMQ adapter.
package rabbitmqconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// AttributePermissionTemplates is the adapter.Connection.Attributes key.
	AttributePermissionTemplates = "rabbitmq_permission_templates"

	MaxTemplates         = 64
	MaxKeyLength         = 64
	MaxNameLength        = 128
	MaxDescriptionLength = 512
	MaxVhostLength       = 255
	MaxRegexLength       = 512
)

var templateKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// PermissionTemplate is an allowlisted RabbitMQ configure/write/read tuple.
// It contains no credential material and is safe to send to a connector.
type PermissionTemplate struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Vhost       string `json:"vhost"`
	Configure   string `json:"configure"`
	Write       string `json:"write"`
	Read        string `json:"read"`
	Dangerous   bool   `json:"dangerous"`
}

// IsBroad reports whether any dimension has an obviously unrestricted arm.
// It intentionally recognizes only spellings representable by the safe
// permission-regex subset rather than trying to prove regex equivalence.
func IsBroad(template PermissionTemplate) bool {
	return isUnrestrictedRegex(template.Configure) ||
		isUnrestrictedRegex(template.Write) ||
		isUnrestrictedRegex(template.Read)
}

// Validate rejects ambiguous, unsafe or unbounded template configuration.
// Permission regexes are restricted further than RE2; see
// ValidatePermissionRegex for the supported subset.
func Validate(templates []PermissionTemplate) error {
	if len(templates) > MaxTemplates {
		return fmt.Errorf("rabbitmq_permission_templates has %d entries; maximum is %d", len(templates), MaxTemplates)
	}
	keys := make(map[string]struct{}, len(templates))
	names := make(map[string]struct{}, len(templates))
	tuples := make(map[[4]string]struct{}, len(templates))
	for i, template := range templates {
		field := fmt.Sprintf("rabbitmq_permission_templates[%d]", i)
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
		if err := validateText(field+".vhost", template.Vhost, MaxVhostLength); err != nil {
			return err
		}
		for name, expression := range map[string]string{
			"configure": template.Configure,
			"write":     template.Write,
			"read":      template.Read,
		} {
			if err := validateText(field+"."+name, expression, MaxRegexLength); err != nil {
				return err
			}
			if err := ValidatePermissionRegex(expression); err != nil {
				return fmt.Errorf("%s.%s is outside the safe regex subset: %w", field, name, err)
			}
		}
		if isUnrestrictedRegex(template.Configure) &&
			isUnrestrictedRegex(template.Write) &&
			isUnrestrictedRegex(template.Read) {
			return fmt.Errorf("%s duplicates legacy full vhost access (.*/.*/.*)", field)
		}
		if _, exists := keys[template.Key]; exists {
			return fmt.Errorf("rabbitmq_permission_templates key %q is duplicated", template.Key)
		}
		if _, exists := names[template.Name]; exists {
			return fmt.Errorf("rabbitmq_permission_templates name %q is duplicated", template.Name)
		}
		tuple := [4]string{template.Vhost, template.Configure, template.Write, template.Read}
		if _, exists := tuples[tuple]; exists {
			return fmt.Errorf("rabbitmq_permission_templates permission tuple for vhost %q is duplicated", template.Vhost)
		}
		keys[template.Key] = struct{}{}
		names[template.Name] = struct{}{}
		tuples[tuple] = struct{}{}
	}
	return nil
}

// ValidatePermissionRegex accepts only `.*` or anchored literal/wildcard arms
// with at most one non-nested parenthesized alternation.
func ValidatePermissionRegex(expression string) error {
	// ^$ is RabbitMQ's conventional intentionally-denied dimension.
	if expression == ".*" || expression == "^$" {
		return nil
	}
	if len(expression) < 3 || expression[0] != '^' || expression[len(expression)-1] != '$' {
		return errors.New("must be `.*` or start with `^` and end with `$`")
	}

	body := expression[1 : len(expression)-1]

	startsGroup := body[0] == '('
	endsGroup := body[len(body)-1] == ')' && !isEscaped(body, len(body)-1)
	if startsGroup || endsGroup {
		if len(body) < 3 || !startsGroup || !endsGroup {
			return errors.New("parentheses must wrap the whole expression body")
		}
		arms, err := splitAlternation(body[1 : len(body)-1])
		if err != nil {
			return err
		}
		// A redundant group is not part of the subset. Keep the common full
		// wildcard spelling because it is semantically equivalent to legacy
		// access and must be detected as such.
		if len(arms) == 1 && arms[0] != ".*" {
			return errors.New("parenthesized body must contain an alternation")
		}
		for _, arm := range arms {
			if err := validateRegexArm(arm); err != nil {
				return err
			}
		}
	} else {
		arms, err := splitAlternation(body)
		if err != nil {
			return err
		}
		if len(arms) != 1 {
			return errors.New("alternation must be wrapped in parentheses")
		}
		if err := validateRegexArm(arms[0]); err != nil {
			return err
		}
	}

	if _, err := regexp.Compile(expression); err != nil {
		return fmt.Errorf("invalid RE2 expression: %w", err)
	}
	return nil
}

func splitAlternation(body string) ([]string, error) {
	arms := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			if i+1 >= len(body) {
				return nil, errors.New("dangling escape")
			}
			i++
		case '(', ')':
			return nil, errors.New("nested or partial groups are not allowed")
		case '|':
			if i == start {
				return nil, errors.New("alternation arms must not be empty")
			}
			arms = append(arms, body[start:i])
			start = i + 1
		}
	}
	if start == len(body) {
		return nil, errors.New("alternation arms must not be empty")
	}
	return append(arms, body[start:]), nil
}

func validateRegexArm(arm string) error {
	if arm == "" {
		return errors.New("expression arm must not be empty")
	}
	for i := 0; i < len(arm); i++ {
		ch := arm[i]
		switch {
		case isASCIILetterOrDigit(ch) || ch == '_' || ch == '-' || ch == '/' || ch == ':':
			continue
		case ch == '.' && i+1 < len(arm) && arm[i+1] == '*':
			i++
		case ch == '\\':
			if i+1 >= len(arm) {
				return errors.New("dangling escape")
			}
			i++
			if !isASCIIPunctuation(arm[i]) {
				return errors.New("only literal punctuation may be escaped")
			}
		default:
			return errors.New("only ASCII literals, escaped punctuation, and `.*` are allowed")
		}
	}
	return nil
}

func isASCIILetterOrDigit(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func isASCIIPunctuation(ch byte) bool {
	return ch >= '!' && ch <= '/' || ch >= ':' && ch <= '@' || ch >= '[' && ch <= '`' || ch >= '{' && ch <= '~'
}

func isEscaped(value string, index int) bool {
	escapes := 0
	for i := index - 1; i >= 0 && value[i] == '\\'; i-- {
		escapes++
	}
	return escapes%2 == 1
}

func isUnrestrictedRegex(expression string) bool {
	if expression == ".*" {
		return true
	}
	if len(expression) < 3 || expression[0] != '^' || expression[len(expression)-1] != '$' {
		return false
	}
	body := expression[1 : len(expression)-1]
	if len(body) >= 2 && body[0] == '(' && body[len(body)-1] == ')' {
		body = body[1 : len(body)-1]
	}
	arms, err := splitAlternation(body)
	if err != nil {
		return false
	}
	for _, arm := range arms {
		if armIsUnrestricted(arm) {
			return true
		}
	}
	return false
}

func armIsUnrestricted(arm string) bool {
	if arm == "" || len(arm)%2 != 0 {
		return false
	}
	for i := 0; i < len(arm); i += 2 {
		if arm[i:i+2] != ".*" {
			return false
		}
	}
	return true
}

// FromAttributes restores typed templates after either a direct projection or
// a JSON connector round-trip (where map values decode as []any/map[string]any).
func FromAttributes(attributes map[string]any) ([]PermissionTemplate, error) {
	value, ok := attributes[AttributePermissionTemplates]
	if !ok || value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", AttributePermissionTemplates, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var templates []PermissionTemplate
	if err := dec.Decode(&templates); err != nil {
		return nil, fmt.Errorf("decode %s: %w", AttributePermissionTemplates, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: trailing data", AttributePermissionTemplates)
	}
	if err := Validate(templates); err != nil {
		return nil, err
	}
	return templates, nil
}

func validateText(field, value string, max int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", field, max)
	}
	return nil
}
