package directory

import (
	"fmt"
	"os"
	"strings"

	"github.com/ArtefactoO/grantor/internal/secret"
)

// Разбор конфигурации каталога из окружения.
//
// Живёт в самом пакете, а не в cmd: провайдер нужен обоим бинарям — worker
// сверяет статусы для offboarding-детекции, api заводит принципалов из
// каталога. Копия разбора в двух main разошлась бы при первом же новом
// параметре, и один бинарь начал бы понимать каталог иначе, чем другой.

// FromEnv собирает провайдер по GRANTOR_IDP_MODE.
//
// Пустой режим — nil без ошибки: каталог не подключён, это безопасное
// умолчание (поллинг выключен, импорт отвечает 501). Неизвестный режим —
// ошибка: молча игнорировать опечатку в конфигурации нельзя, иначе
// установка тихо работала бы без каталога.
func FromEnv() (Provider, error) {
	switch mode := strings.TrimSpace(os.Getenv("GRANTOR_IDP_MODE")); mode {
	case "":
		return nil, nil
	case "ldap":
		return ldapFromEnv()
	case "authentik":
		return authentikFromEnv()
	case "static":
		// Mock-провайдер для dev-контура и стендов без каталога: статусы из
		// статических списков, сети нет. Боевые каталоги подключаются
		// режимами ldap (AD напрямую) и authentik (его собственный API).
		return NewStatic(
			splitCSV(os.Getenv("GRANTOR_IDP_STATIC_DISABLED")),
			splitCSV(os.Getenv("GRANTOR_IDP_STATIC_MISSING")),
		).WithRoster(splitCSV(os.Getenv("GRANTOR_IDP_STATIC_SUBJECTS"))), nil
	default:
		return nil, fmt.Errorf("unknown GRANTOR_IDP_MODE %q (supported: empty, \"ldap\", \"authentik\", \"static\")", mode)
	}
}

// authentikFromEnv собирает провайдер Authentik из GRANTOR_IDP_AUTHENTIK_*.
func authentikFromEnv() (Provider, error) {
	var caPEM []byte
	if caFile := os.Getenv("GRANTOR_IDP_AUTHENTIK_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read GRANTOR_IDP_AUTHENTIK_CA_FILE: %w", err)
		}
		caPEM = pem
	}
	provider, err := NewAuthentik(AuthentikConfig{
		BaseURL:   os.Getenv("GRANTOR_IDP_AUTHENTIK_URL"),
		Token:     secret.FromString(os.Getenv("GRANTOR_IDP_AUTHENTIK_TOKEN")),
		Group:     os.Getenv("GRANTOR_IDP_AUTHENTIK_GROUP"),
		CACertPEM: caPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("create authentik directory provider: %w", err)
	}
	return provider, nil
}

// ldapFromEnv собирает LDAP-провайдер из GRANTOR_IDP_LDAP_*.
func ldapFromEnv() (Provider, error) {
	var caPEM []byte
	if caFile := os.Getenv("GRANTOR_IDP_LDAP_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read GRANTOR_IDP_LDAP_CA_FILE: %w", err)
		}
		caPEM = pem
	}
	provider, err := NewLDAP(LDAPConfig{
		URL:                  os.Getenv("GRANTOR_IDP_LDAP_URL"),
		BindDN:               os.Getenv("GRANTOR_IDP_LDAP_BIND_DN"),
		BindPassword:         secret.FromString(os.Getenv("GRANTOR_IDP_LDAP_BIND_PASSWORD")),
		BaseDN:               os.Getenv("GRANTOR_IDP_LDAP_BASE_DN"),
		UserFilter:           os.Getenv("GRANTOR_IDP_LDAP_USER_FILTER"),
		DisabledFilter:       os.Getenv("GRANTOR_IDP_LDAP_DISABLED_FILTER"),
		SearchFilter:         os.Getenv("GRANTOR_IDP_LDAP_SEARCH_FILTER"),
		SearchAllFilter:      os.Getenv("GRANTOR_IDP_LDAP_SEARCH_ALL_FILTER"),
		SubjectAttribute:     os.Getenv("GRANTOR_IDP_LDAP_SUBJECT_ATTRIBUTE"),
		DisplayNameAttribute: os.Getenv("GRANTOR_IDP_LDAP_DISPLAY_NAME_ATTRIBUTE"),
		CACertPEM:            caPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("create ldap directory provider: %w", err)
	}
	return provider, nil
}

// ProviderNameFromEnv возвращает значение principals.external_provider для
// принципалов этого каталога (GRANTOR_IDP_PROVIDER). Оно связывает
// заведённых принципалов с поллингом статусов, поэтому импорт и поллинг
// обязаны читать его из одного места.
func ProviderNameFromEnv() string {
	return strings.TrimSpace(os.Getenv("GRANTOR_IDP_PROVIDER"))
}

// splitCSV разбирает csv-список, обрезая пробелы и отбрасывая пустые.
func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
