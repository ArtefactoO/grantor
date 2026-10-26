package directory

// Референсный LDAP-провайдер identity directory: самый распространённый
// poll-able корпоративный протокол каталога (Active Directory, FreeIPA,
// OpenLDAP). Статус субъекта определяется двумя server-side поисками:
// user filter находит запись (нет записи → StatusMissing), затем — если
// задан disabled filter — конъюнкция user filter и disabled filter
// проверяет признак блокировки (совпадение → StatusDisabled). Фильтр
// блокировки специфичен для каталога и задаётся конфигурацией, например
// AD: (userAccountControl:1.2.840.113556.1.4.803:=2).
//
// Значение subject экранируется ldap.EscapeFilter перед подстановкой в
// шаблон фильтра: subject из metadata database не может инжектировать
// собственные условия в LDAP-запрос.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/ArtefactoO/grantor/internal/secret"
)

// defaultUserFilter — шаблон поиска субъекта по умолчанию: субъект
// принципала — корпоративный email (claim email OIDC-сессий, раздел 7.1
// архитектуры).
const defaultUserFilter = "(mail=%s)"

// Значения по умолчанию перечисления каталога. Ориентированы на Authentik
// LDAP outpost и совместимы с AD/OpenLDAP: у всех трёх человек — запись с
// классом person и атрибутом mail.
const (
	// defaultSearchFilter — поиск по подстроке в адресе, полном имени и
	// логине. Три атрибута, потому что оператор ищет по тому, что помнит:
	// в Authentik cn — это логин, а полное имя лежит в displayName, тогда
	// как в AD осмысленны оба.
	defaultSearchFilter = "(&(objectClass=person)(|(mail=*%s*)(displayName=*%s*)(cn=*%s*)))"
	// defaultSearchAllFilter — перечисление людей с настоящим адресом.
	//
	// Условие `mail=*@*`, а не `mail=*`: второе проверяет лишь НАЛИЧИЕ
	// атрибута, а служебные учётные записи Authentik (outpost service
	// accounts) отдают mail пустой строкой и потому проходили фильтр,
	// попадая в список кандидатов на импорт. Требование символа @
	// отсекает их и одинаково работает в AD.
	defaultSearchAllFilter = "(&(objectClass=person)(mail=*@*))"
	// defaultSubjectAttribute совпадает с атрибутом defaultUserFilter.
	defaultSubjectAttribute = "mail"
	// defaultDisplayNameAttribute — имя для показа оператору. displayName,
	// а не cn: в Authentik LDAP cn содержит логин, и оператор видел бы
	// «ivan.petrov» вместо «Иван Петров». В AD displayName тоже заполнен,
	// поэтому умолчание годится обоим; запасной атрибут — cn.
	defaultDisplayNameAttribute = "displayName"
	// fallbackDisplayNameAttribute используется, когда основной атрибут у
	// записи пуст: имя показать всё равно нужно.
	fallbackDisplayNameAttribute = "cn"
)

const (
	// dialTimeout — предел установления соединения с каталогом.
	dialTimeout = 10 * time.Second
	// requestTimeout — предел одного LDAP-запроса.
	requestTimeout = 15 * time.Second
)

// LDAPConfig — конфигурация LDAP-провайдера (env-переменные
// GRANTOR_IDP_LDAP_*, см. cmd/worker).
type LDAPConfig struct {
	// URL каталога: ldap:// или ldaps://.
	URL string
	// BindDN — DN сервисной учётки для bind. Пустой = anonymous bind.
	BindDN string
	// BindPassword — пароль bind. Хранится в secret.Value и не попадает в
	// логи/ошибки ни в одном представлении.
	BindPassword secret.Value
	// BaseDN — база поиска субъектов.
	BaseDN string
	// UserFilter — шаблон фильтра поиска субъекта с одним %s, в который
	// подставляется экранированный subject. Пустой = defaultUserFilter.
	UserFilter string
	// DisabledFilter — необязательный фильтр, которому удовлетворяют
	// заблокированные записи каталога. Пустой = детекция только по
	// отсутствию записи (StatusMissing).
	DisabledFilter string
	// SearchFilter — шаблон фильтра перечисления каталога с одним %s, в
	// который подставляется экранированная строка поиска. Пустой =
	// defaultSearchFilter. Отличается от UserFilter тем, что ищет по
	// подстроке и по нескольким атрибутам: UserFilter адресует ровно одного
	// известного субъекта, а этот — отбирает кандидатов для импорта.
	SearchFilter string
	// SearchAllFilter — фильтр перечисления каталога целиком (пустой
	// запрос). Пустой = defaultSearchAllFilter. Именно он ограничивает,
	// кого организация считает импортируемыми людьми: без него массовая
	// загрузка втянула бы служебные записи каталога.
	SearchAllFilter string
	// SubjectAttribute — атрибут, попадающий в principals.external_subject.
	// Пустой = defaultSubjectAttribute. Обязан совпадать с атрибутом
	// UserFilter, иначе импортированный принципал сразу окажется missing.
	SubjectAttribute string
	// DisplayNameAttribute — атрибут отображаемого имени. Пустой =
	// defaultDisplayNameAttribute.
	DisplayNameAttribute string
	// CACertPEM — необязательный PEM-бандл доверенных CA для ldaps.
	// Пустой = системные корни.
	CACertPEM []byte
}

// LDAPProvider — Provider поверх LDAP-каталога. Создаётся NewLDAP;
// соединение устанавливается на каждый вызов Statuses (прогон
// обслуживания), а не держится постоянно.
type LDAPProvider struct {
	cfg     LDAPConfig
	tlsConf *tls.Config
}

// Проверка соответствия порту на этапе компиляции.
var _ Provider = (*LDAPProvider)(nil)

// NewLDAP валидирует конфигурацию и возвращает LDAP-провайдер. Ошибки
// конфигурации (пустой URL/BaseDN, не-LDAP схема, некорректные фильтры,
// нечитаемый CA PEM) обнаруживаются здесь, при старте worker, а не на
// первом прогоне обслуживания.
func NewLDAP(cfg LDAPConfig) (*LDAPProvider, error) {
	if cfg.URL == "" {
		return nil, errors.New("directory: ldap: url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("directory: ldap: parse url: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("directory: ldap: unsupported url scheme %q (want ldap or ldaps)", u.Scheme)
	}
	if cfg.BaseDN == "" {
		return nil, errors.New("directory: ldap: base dn is required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = defaultUserFilter
	}
	// Валидация шаблона: подстановка пробного субъекта обязана давать
	// синтаксически корректный LDAP-фильтр.
	if cfg.SearchFilter == "" {
		cfg.SearchFilter = defaultSearchFilter
	}
	if cfg.SearchAllFilter == "" {
		cfg.SearchAllFilter = defaultSearchAllFilter
	}
	if cfg.SubjectAttribute == "" {
		cfg.SubjectAttribute = defaultSubjectAttribute
	}
	if cfg.DisplayNameAttribute == "" {
		cfg.DisplayNameAttribute = defaultDisplayNameAttribute
	}
	if _, err := ldap.CompileFilter(expandSearchFilter(cfg.SearchFilter, "probe")); err != nil {
		return nil, fmt.Errorf("directory: ldap: invalid search filter %q: %w", cfg.SearchFilter, err)
	}
	if _, err := ldap.CompileFilter(cfg.SearchAllFilter); err != nil {
		return nil, fmt.Errorf("directory: ldap: invalid search-all filter %q: %w", cfg.SearchAllFilter, err)
	}

	probe, err := searchFilter(cfg.UserFilter, "probe@example.com")
	if err != nil {
		return nil, err
	}
	if _, err := ldap.CompileFilter(probe); err != nil {
		return nil, fmt.Errorf("directory: ldap: invalid user filter %q: %w", cfg.UserFilter, err)
	}
	if cfg.DisabledFilter != "" {
		if _, err := ldap.CompileFilter(cfg.DisabledFilter); err != nil {
			return nil, fmt.Errorf("directory: ldap: invalid disabled filter %q: %w", cfg.DisabledFilter, err)
		}
	}

	var tlsConf *tls.Config
	if len(cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, errors.New("directory: ldap: ca pem contains no valid certificates")
		}
		tlsConf = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &LDAPProvider{cfg: cfg, tlsConf: tlsConf}, nil
}

// searchFilter подставляет экранированный subject в шаблон фильтра.
// Шаблон обязан содержать ровно один placeholder %s. Подстановка идёт
// строковой заменой (не fmt), поэтому прочие %-последовательности шаблона
// не интерпретируются; subject экранируется ldap.EscapeFilter — значения
// вида "*)(uid=*" остаются литералом и не расширяют фильтр.
func searchFilter(template, subject string) (string, error) {
	if strings.Count(template, "%s") != 1 {
		return "", fmt.Errorf("directory: ldap: filter template %q must contain exactly one %%s", template)
	}
	return strings.Replace(template, "%s", ldap.EscapeFilter(subject), 1), nil
}

// Statuses возвращает состояние каждого subject в каталоге (контракт —
// см. Provider). Соединение и bind выполняются один раз на вызов и
// переиспользуются для всех субъектов прогона.
func (p *LDAPProvider) Statuses(ctx context.Context, subjects []string) (map[string]Status, error) {
	out := make(map[string]Status, len(subjects))
	if len(subjects) == 0 {
		return out, nil
	}

	conn, err := p.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck
	conn.SetTimeout(requestTimeout)

	if p.cfg.BindDN != "" {
		// Текст ошибки go-ldap не содержит пароль; сам пароль раскрывается
		// только в аргумент Bind и нигде не сохраняется.
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword.RevealString()); err != nil {
			return nil, fmt.Errorf("directory: ldap: bind as %q: %w", p.cfg.BindDN, err)
		}
	}

	for _, subject := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("directory: ldap: statuses: %w", err)
		}
		st, err := p.subjectStatus(conn, subject)
		if err != nil {
			return nil, err
		}
		out[subject] = st
	}
	return out, nil
}

// dial устанавливает соединение с каталогом. TLS-конфигурация (custom CA)
// применяется только для ldaps.
func (p *LDAPProvider) dial() (*ldap.Conn, error) {
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout})}
	if p.tlsConf != nil {
		opts = append(opts, ldap.DialWithTLSConfig(p.tlsConf))
	}
	conn, err := ldap.DialURL(p.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("directory: ldap: dial %s: %w", p.cfg.URL, err)
	}
	return conn, nil
}

// subjectStatus определяет статус одного субъекта: запись не найдена →
// missing; найдена и совпадает с disabled filter → disabled; иначе active.
func (p *LDAPProvider) subjectStatus(conn *ldap.Conn, subject string) (Status, error) {
	found, err := p.exists(conn, p.cfg.UserFilter, subject)
	if err != nil {
		return "", err
	}
	if !found {
		return StatusMissing, nil
	}
	if p.cfg.DisabledFilter == "" {
		return StatusActive, nil
	}
	disabled, err := p.exists(conn, "(&"+p.cfg.UserFilter+p.cfg.DisabledFilter+")", subject)
	if err != nil {
		return "", err
	}
	if disabled {
		return StatusDisabled, nil
	}
	return StatusActive, nil
}

// exists сообщает, есть ли в каталоге запись, удовлетворяющая шаблону
// фильтра с подставленным subject. Атрибуты не запрашиваются ("1.1"):
// нужен только факт существования.
func (p *LDAPProvider) exists(conn *ldap.Conn, filterTemplate, subject string) (bool, error) {
	filter, err := searchFilter(filterTemplate, subject)
	if err != nil {
		return false, err
	}
	req := ldap.NewSearchRequest(
		p.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(requestTimeout.Seconds()), false,
		filter,
		[]string{"1.1"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return false, fmt.Errorf("directory: ldap: search %q under %q: %w", filter, p.cfg.BaseDN, err)
	}
	return len(res.Entries) > 0, nil
}

// Проверка соответствия контракту перечисления на этапе компиляции.
var _ Searcher = (*LDAPProvider)(nil)

// expandSearchFilter подставляет экранированную строку поиска во ВСЕ
// вхождения %s шаблона: фильтр поиска обычно проверяет несколько атрибутов
// (mail и cn), и строка нужна в каждом. Замена строковая, поэтому прочие
// %-последовательности шаблона не интерпретируются, а ldap.EscapeFilter не
// даёт значению расширить фильтр.
func expandSearchFilter(template, query string) string {
	return strings.ReplaceAll(template, "%s", ldap.EscapeFilter(query))
}

// Search перечисляет субъекты каталога (контракт — см. Searcher).
//
// Пустой query перечисляет каталог по SearchAllFilter, непустой отбирает по
// SearchFilter. Записи без атрибута subject пропускаются: заводить
// принципала, которого потом нечем сверять с каталогом, бессмысленно.
func (p *LDAPProvider) Search(ctx context.Context, query string, limit int) ([]Entry, error) {
	if limit <= 0 {
		return nil, errors.New("directory: ldap: search limit must be positive")
	}

	conn, err := p.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck
	conn.SetTimeout(requestTimeout)

	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword.RevealString()); err != nil {
			return nil, fmt.Errorf("directory: ldap: bind as %q: %w", p.cfg.BindDN, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("directory: ldap: search: %w", err)
	}

	filter := p.cfg.SearchAllFilter
	if strings.TrimSpace(query) != "" {
		filter = expandSearchFilter(p.cfg.SearchFilter, strings.TrimSpace(query))
	}

	// SizeLimit на стороне каталога: не тянем в память лишнее, даже если
	// под фильтр попадают десятки тысяч записей.
	req := ldap.NewSearchRequest(
		p.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		limit, int(requestTimeout.Seconds()), false,
		filter,
		[]string{p.cfg.SubjectAttribute, p.cfg.DisplayNameAttribute, fallbackDisplayNameAttribute},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		// Превышение SizeLimit — штатный ответ каталога на слишком широкий
		// запрос, а не сбой: отдаём то, что успели получить.
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || res == nil {
			return nil, fmt.Errorf("directory: ldap: search %q under %q: %w", filter, p.cfg.BaseDN, err)
		}
	}

	out := make([]Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		subject := strings.TrimSpace(e.GetAttributeValue(p.cfg.SubjectAttribute))
		if subject == "" {
			continue
		}
		status, err := p.subjectStatus(conn, subject)
		if err != nil {
			return nil, err
		}
		displayName := strings.TrimSpace(e.GetAttributeValue(p.cfg.DisplayNameAttribute))
		if displayName == "" {
			displayName = strings.TrimSpace(e.GetAttributeValue(fallbackDisplayNameAttribute))
		}
		out = append(out, Entry{
			Subject:     subject,
			DisplayName: displayName,
			Status:      status,
		})
	}
	return out, nil
}
