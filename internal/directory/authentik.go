package directory

// Провайдер identity directory поверх REST API Authentik.
//
// Зачем он рядом с LDAP-провайдером. Authentik умеет отдавать каталог и по
// LDAP — через outpost, — но outpost это отдельный развёрнутый компонент,
// свои учётные данные и своя точка отказа. Когда Authentik уже является
// OIDC-провайдером grantor, его собственный API отвечает на оба нужных
// вопроса (жив ли субъект, кто есть в каталоге) без этого промежуточного
// звена, поэтому ходить в AD параллельно тоже не требуется: Authentik
// зеркалит AD и знает про блокировки.
//
// Соответствие статусов. Authentik присваивает is_active=false субъекту,
// заблокированному в исходном каталоге (для AD-источника это
// userAccountControl с битом ACCOUNTDISABLE), — это StatusDisabled. Если
// у LDAP-источника включён delete_not_found_objects, исчезнувший из AD
// субъект удаляется и из Authentik — это StatusMissing. При выключенной
// опции удалённый в AD человек останется в Authentik активным, и
// offboarding-детекция его не увидит; это свойство инсталляции, а не
// провайдера.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/secret"
)

const (
	// authentikUsersPath — коллекция пользователей ядра Authentik.
	authentikUsersPath = "/api/v3/core/users/"
	// authentikDefaultTimeout — предел одного запроса к API.
	authentikDefaultTimeout = 15 * time.Second
	// authentikErrorBodyLimit — сколько байт тела ошибочного ответа попадает
	// в текст ошибки. Ответ Authentik об ошибке короткий и не содержит
	// секретов, но обрезка защищает от неожиданного HTML-ответа прокси.
	authentikErrorBodyLimit = 512
)

// authentikPersonTypes — типы учётных записей, которые считаются людьми.
//
// Фильтр нужен обоим методам: в каталоге живут ещё и service accounts
// (у Authentik это отдельный type), заводить их принципалами нельзя, а их
// появление в результатах поиска выглядело бы как настоящий человек. Это
// та же задача, которую LDAP-провайдер решает костылём `mail=*@*`, но
// здесь у неё есть штатное поле.
var authentikPersonTypes = []string{"internal", "external"}

// AuthentikConfig — конфигурация провайдера (env GRANTOR_IDP_AUTHENTIK_*).
type AuthentikConfig struct {
	// BaseURL — корень инсталляции, например https://atk.example.com.
	// Путь API дописывается провайдером. Обязателен.
	BaseURL string
	// Token — API-токен Authentik. Достаточно прав на чтение
	// пользователей; хранится в secret.Value и не попадает в логи и ошибки.
	// Обязателен.
	Token secret.Value
	// Group — необязательное имя группы Authentik, которым ограничивается
	// перечисление каталога.
	//
	// Действует только на Search: он отвечает на вопрос «кого можно
	// завести», и сузить его до одной группы — законное решение
	// организации. На Statuses фильтр НЕ распространяется намеренно: иначе
	// исключение человека из группы читалось бы как StatusMissing, то есть
	// как удаление из каталога, и запускало бы offboarding по изменению
	// прав, а не по увольнению.
	Group string
	// Timeout — предел одного HTTP-запроса; пустой = authentikDefaultTimeout.
	Timeout time.Duration
	// CACertPEM — необязательный PEM-бандл доверенных CA. Пустой =
	// системные корни.
	CACertPEM []byte
}

// AuthentikProvider — Provider и Searcher поверх API Authentik.
type AuthentikProvider struct {
	baseURL *url.URL
	token   secret.Value
	group   string
	http    *http.Client
}

// Проверки соответствия портам на этапе компиляции.
var (
	_ Provider            = (*AuthentikProvider)(nil)
	_ Searcher            = (*AuthentikProvider)(nil)
	_ APIIdentityProvider = (*AuthentikProvider)(nil)
)

// NewAuthentik валидирует конфигурацию и возвращает провайдер. Ошибки
// конфигурации обнаруживаются здесь, при старте процесса, а не на первом
// прогоне обслуживания.
func NewAuthentik(cfg AuthentikConfig) (*AuthentikProvider, error) {
	raw := strings.TrimSpace(cfg.BaseURL)
	if raw == "" {
		return nil, errors.New("directory: authentik: base url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("directory: authentik: parse base url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("directory: authentik: unsupported url scheme %q (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("directory: authentik: base url %q has no host", raw)
	}
	if cfg.Token.RevealString() == "" {
		return nil, errors.New("directory: authentik: api token is required")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = authentikDefaultTimeout
	}
	client := &http.Client{Timeout: timeout}
	if len(cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, errors.New("directory: authentik: ca pem contains no valid certificates")
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}

	return &AuthentikProvider{
		baseURL: u,
		token:   cfg.Token,
		group:   strings.TrimSpace(cfg.Group),
		http:    client,
	}, nil
}

// authentikUser — та часть представления пользователя, которая нужна
// провайдеру. Остальные поля ответа игнорируются: провайдер не должен
// ломаться от расширения схемы в новой версии Authentik.
type authentikUser struct {
	UID      string          `json:"uid"`
	Email    string          `json:"email"`
	Groups   json.RawMessage `json:"groups_obj"`
	Username string          `json:"username"`
	Name     string          `json:"name"`
	IsActive bool            `json:"is_active"`
}

// APIIdentity requires an exact, unique username and an immutable uid. It does
// not use the integer API pk or assume that an OIDC subject has the pk format.
func (p *AuthentikProvider) APIIdentity(ctx context.Context, username string) (APIIdentity, error) {
	query := url.Values{}
	query.Set("username", username)
	query.Set("page_size", "2")
	page, err := p.fetchUsers(ctx, query)
	if err != nil {
		return APIIdentity{}, err
	}
	var matches []authentikUser
	for _, u := range page.Results {
		if u.Username == username {
			matches = append(matches, u)
		}
	}
	if len(matches) == 0 {
		return APIIdentity{Username: username, Status: StatusMissing}, nil
	}
	if len(matches) != 1 || matches[0].UID == "" || matches[0].Email == "" {
		return APIIdentity{}, errors.New("directory: authentik: incomplete or ambiguous API identity")
	}
	u := matches[0]
	var groups []struct {
		Name string `json:"name"`
	}
	if len(u.Groups) == 0 || json.Unmarshal(u.Groups, &groups) != nil {
		return APIIdentity{}, errors.New("directory: authentik: missing API identity groups")
	}
	i := APIIdentity{UID: u.UID, Username: u.Username, Email: u.Email, Status: StatusActive, Groups: make([]string, 0, len(groups))}
	if !u.IsActive {
		i.Status = StatusDisabled
	}
	for _, g := range groups {
		if g.Name == "" {
			return APIIdentity{}, errors.New("directory: authentik: incomplete API identity group")
		}
		i.Groups = append(i.Groups, g.Name)
	}
	return i, nil
}

// authentikUserPage — страница коллекции пользователей.
type authentikUserPage struct {
	Results []authentikUser `json:"results"`
}

// Statuses возвращает состояние каждого subject (контракт — см. Provider).
//
// Субъект здесь — username Authentik: провайдер обязан искать по тому же
// атрибуту, который OIDC отдаёт в claim sub (sub_mode=user_username), иначе
// вошедший через SSO принципал не сойдётся с собственной записью каталога.
//
// Запрос делается на каждый subject: точечная фильтрация по username
// вместо выгрузки всего каталога. Каталог организации может содержать
// десятки тысяч записей, а сверяются обычно единицы принципалов.
func (p *AuthentikProvider) Statuses(ctx context.Context, subjects []string) (map[string]Status, error) {
	out := make(map[string]Status, len(subjects))
	if len(subjects) == 0 {
		return out, nil
	}
	for _, subject := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("directory: authentik: statuses: %w", err)
		}
		status, err := p.subjectStatus(ctx, subject)
		if err != nil {
			return nil, err
		}
		out[subject] = status
	}
	return out, nil
}

// subjectStatus определяет статус одного субъекта.
//
// Совпадение по username проверяется ещё раз на стороне grantor: фильтр
// Authentik точный, но полагаться на это в решении об offboarding нельзя —
// изменись семантика фильтра, и чужая запись стала бы поводом считать
// субъекта активным.
func (p *AuthentikProvider) subjectStatus(ctx context.Context, subject string) (Status, error) {
	query := url.Values{}
	query.Set("username", subject)
	query.Set("page_size", "2")

	page, err := p.fetchUsers(ctx, query)
	if err != nil {
		return "", err
	}
	for _, u := range page.Results {
		if u.Username != subject {
			continue
		}
		if u.IsActive {
			return StatusActive, nil
		}
		return StatusDisabled, nil
	}
	return StatusMissing, nil
}

// Search перечисляет субъекты каталога (контракт — см. Searcher).
//
// Пустой query перечисляет каталог, непустой отбирает по подстроке —
// поиск Authentik покрывает username, имя и атрибуты, поэтому оператор
// находит человека и по логину, и по фамилии.
func (p *AuthentikProvider) Search(ctx context.Context, query string, limit int) ([]Entry, error) {
	if limit <= 0 {
		return nil, errors.New("directory: authentik: search limit must be positive")
	}

	params := url.Values{}
	params.Set("page_size", strconv.Itoa(limit))
	for _, t := range authentikPersonTypes {
		params.Add("type", t)
	}
	if q := strings.TrimSpace(query); q != "" {
		params.Set("search", q)
	}
	if p.group != "" {
		params.Set("groups_by_name", p.group)
	}

	page, err := p.fetchUsers(ctx, params)
	if err != nil {
		return nil, err
	}

	out := make([]Entry, 0, len(page.Results))
	for _, u := range page.Results {
		subject := strings.TrimSpace(u.Username)
		if subject == "" {
			// Без субъекта принципала нечем сверять с каталогом: такая
			// запись бесполезна как кандидат на импорт.
			continue
		}
		status := StatusActive
		if !u.IsActive {
			status = StatusDisabled
		}
		displayName := strings.TrimSpace(u.Name)
		if displayName == "" {
			displayName = subject
		}
		out = append(out, Entry{
			Subject:     subject,
			DisplayName: displayName,
			Status:      status,
		})
	}
	return out, nil
}

// fetchUsers выполняет запрос к коллекции пользователей и разбирает ответ.
func (p *AuthentikProvider) fetchUsers(ctx context.Context, params url.Values) (authentikUserPage, error) {
	var page authentikUserPage

	endpoint := *p.baseURL
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + authentikUsersPath
	endpoint.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return page, fmt.Errorf("directory: authentik: build request: %w", err)
	}
	// Токен раскрывается только в заголовок запроса и никуда не
	// сохраняется; URL в тексте ошибок ниже его не содержит.
	req.Header.Set("Authorization", "Bearer "+p.token.RevealString())
	req.Header.Set("Accept", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return page, fmt.Errorf("directory: authentik: request %s: %w", endpoint.Path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, authentikErrorBodyLimit))
		detail := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// Отдельная ветка: недостаточные права токена выглядят как
			// «каталог сломан», и без подсказки это ищут в сети, а не в
			// правах сервисной учётки.
			return page, fmt.Errorf("directory: authentik: api token rejected (http %d): %s", resp.StatusCode, detail)
		}
		return page, fmt.Errorf("directory: authentik: request %s: http %d: %s", endpoint.Path, resp.StatusCode, detail)
	}

	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return page, fmt.Errorf("directory: authentik: decode response: %w", err)
	}
	return page, nil
}
