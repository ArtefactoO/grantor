// Package netguard реализует переиспользуемую проверку сетевых endpoint
// (SSRF-guard) по инвертированной модели allowlist.
//
// Grantor по определению подключается к приватным БД, поэтому приватные
// диапазоны блокировать нельзя. Вместо блок-листа применяется:
//
//   - жёсткий блок cloud-metadata адресов, loopback самого control-plane,
//     link-local, unspecified и multicast — всегда, независимо от allowlist;
//   - опциональный allowlist разрешённых CIDR / портов / DNS-суффиксов,
//     которым admin может сузить доступ; пустой allowlist = разрешено всё,
//     кроме жёстких блоков;
//   - резолв host и проверка каждого полученного IP (а не только строки) —
//     против DNS-rebinding. Резолв best-effort: он валидирует ввод на этапе
//     создания connection, но строгая проверка IP — на dial-time, поэтому
//     нерезолвящийся host при пустой политике не блокируется.
//
// См. docs/adr/0007-security-hardening-decisions.md (раздел «SSRF») и
// docs/threat-model.md (раздел 3.4).
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Ошибки проверки endpoint. Тексты содержат только категорию причины, но
// никогда сам адрес: раскрытие внутренней топологии в ошибке недопустимо.
var (
	// ErrBlockedAddress — endpoint резолвится в адрес из жёсткого блок-листа
	// (cloud-metadata, loopback, link-local, unspecified, multicast). Блок
	// действует всегда, независимо от allowlist.
	ErrBlockedAddress = errors.New("address is blocked by network policy")
	// ErrNotAllowed — endpoint не попал в непустой allowlist (CIDR / DNS /
	// порт) либо host не удалось разрешить (fail-closed).
	ErrNotAllowed = errors.New("address is not permitted by network policy")
	// ErrDialFailed скрывает конкретный адрес и низкоуровневую сетевую
	// ошибку. Adapters могут безопасно вернуть её наружу, не раскрывая
	// внутреннюю топологию target.
	ErrDialFailed = errors.New("endpoint dial failed")
)

// blockedMetadataCIDRs — cloud-metadata адреса, заблокированные всегда:
// AWS/GCP/Azure link-local metadata (169.254.169.254), AWS IMDS по IPv6
// (fd00:ec2::254) и Alibaba Cloud (100.100.100.100). Отдельный список
// нужен, потому что 100.100.100.100 (CGN-диапазон) и fd00:ec2::254 (ULA)
// не покрываются стандартными предикатами net.IP, а для 169.254.169.254
// он даёт более точную причину, чем общий link-local.
var blockedMetadataCIDRs = mustCIDRs(
	"169.254.169.254/32",
	"fd00:ec2::254/128",
	"100.100.100.100/32",
)

// mustCIDRs парсит встроенные CIDR блок-листа; ошибка формата — дефект
// кода, поэтому panic на этапе инициализации пакета.
func mustCIDRs(cidrs ...string) []net.IPNet {
	out := make([]net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("netguard: invalid built-in CIDR " + c + ": " + err.Error())
		}
		out = append(out, *n)
	}
	return out
}

// Policy — сетевая политика проверки endpoint. Zero value (все поля пусты)
// = разрешено всё, кроме жёстких блоков.
//
// Host-allowlist образуют AllowedCIDRs и AllowedDNSSuffixes вместе: если
// хотя бы один из них задан, host обязан совпасть. AllowedPorts — отдельное
// измерение: если список задан, port обязан в него попасть.
type Policy struct {
	// PrivateKubernetesDNS requires canonical Kubernetes DNS and private IPs
	// on every dial. It is an internal signed target profile, not an env bypass.
	PrivateKubernetesDNS bool
	// AllowedCIDRs — разрешённые сети. Литеральный IP или все резолвленные
	// IP host должны попасть в один из CIDR.
	AllowedCIDRs []net.IPNet
	// AllowedPorts — разрешённые порты; пустой список = любой порт.
	AllowedPorts []int
	// AllowedDNSSuffixes — разрешённые DNS-суффиксы в нижнем регистре с
	// ведущей точкой (например ".internal.example.com").
	AllowedDNSSuffixes []string
}

// ParsePolicy собирает Policy из строковых списков (обычно env csv).
// CIDR парсятся net.ParseCIDR, порты проверяются на диапазон 1..65535,
// DNS-суффиксы нормализуются к нижнему регистру с ведущей точкой. Пустые
// элементы пропускаются; пустые списки дают пустую политику.
func ParsePolicy(cidrs, ports, dnsSuffixes []string) (Policy, error) {
	var p Policy
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return Policy{}, fmt.Errorf("parse allowed CIDR %q: %w", c, err)
		}
		p.AllowedCIDRs = append(p.AllowedCIDRs, *n)
	}
	for _, s := range ports {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return Policy{}, fmt.Errorf("parse allowed port %q: %w", s, err)
		}
		if n < 1 || n > 65535 {
			return Policy{}, fmt.Errorf("allowed port %d is out of range 1..65535", n)
		}
		p.AllowedPorts = append(p.AllowedPorts, n)
	}
	for _, s := range dnsSuffixes {
		if s = normalizeDNSSuffix(s); s != "" {
			p.AllowedDNSSuffixes = append(p.AllowedDNSSuffixes, s)
		}
	}
	return p, nil
}

// normalizeDNSSuffix приводит суффикс к нижнему регистру и гарантирует
// ведущую точку; пустая строка остаётся пустой.
func normalizeDNSSuffix(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, ".") {
		s = "." + s
	}
	return s
}

// CheckEndpoint проверяет endpoint host:port политикой:
//
//   - если host — литеральный IP, проверяется он сам; иначе host резолвится
//     через resolver, и каждый полученный IP проверяется жёстким блоком
//     (DNS-rebinding: блок хотя бы одного IP — отказ всему endpoint);
//   - жёсткий блок (cloud-metadata / loopback / link-local / unspecified /
//     multicast) действует всегда и возвращает ErrBlockedAddress;
//   - при непустом host-allowlist host обязан попасть в AllowedCIDRs или
//     совпасть с AllowedDNSSuffixes, иначе ErrNotAllowed;
//   - при непустом AllowedPorts port обязан попасть в список;
//   - пустая политика после жёстких блоков разрешает endpoint.
//
// Резолв — best-effort: если host не резолвится, при пустой политике
// endpoint разрешается (строгая проверка IP выполняется на dial-time; API
// не должен зависеть от доступности DNS целевой БД). При непустой политике
// нерезолвящийся host допускается только по совпадению DNS-суффикса, иначе
// отказ (fail-closed под активной политикой). resolver == nil трактуется
// как DefaultResolver. Порт 0 означает «не указан» и проходит проверку
// только при пустом AllowedPorts.
func (p Policy) CheckEndpoint(ctx context.Context, host string, port int, resolver Resolver) error {
	literal := net.ParseIP(host)
	var (
		ips        []net.IP
		resolveErr error
	)
	if literal != nil {
		ips = []net.IP{literal}
	} else {
		ips, resolveErr = lookupIP(ctx, host, resolver)
	}

	return p.checkResolvedEndpoint(host, port, literal != nil, ips, resolveErr)
}

// checkResolvedEndpoint применяет policy к уже полученному DNS snapshot.
// GuardedDialer использует тот же snapshot и для проверки, и для реального
// dial, поэтому между этими действиями нет второго DNS lookup.
func (p Policy) checkResolvedEndpoint(host string, port int, literal bool, ips []net.IP, resolveErr error) error {
	if p.PrivateKubernetesDNS && (resolveErr != nil || len(ips) == 0 || (!literal && !IsKubernetesDNSHost(host))) {
		return ErrNotAllowed
	}
	for _, ip := range ips {
		if ip == nil || ip.To16() == nil {
			return ErrNotAllowed
		}
		if reason, blocked := hardBlock(ip); blocked {
			return fmt.Errorf("%w (%s)", ErrBlockedAddress, reason)
		}
		if p.PrivateKubernetesDNS && !ip.IsPrivate() {
			return ErrNotAllowed
		}
	}
	if !p.hostAllowlistEmpty() && !p.hostAllowed(host, literal, ips, resolveErr) {
		return fmt.Errorf("%w (host not in allowlist)", ErrNotAllowed)
	}
	if len(p.AllowedPorts) > 0 && !slices.Contains(p.AllowedPorts, port) {
		return fmt.Errorf("%w (port not in allowlist)", ErrNotAllowed)
	}
	return nil
}

// DialContextFunc совпадает с net.Dialer.DialContext и dial hooks драйверов.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// GuardedDialer атомарно связывает DNS policy-check с реальным TCP dial.
// Имя резолвится ровно один раз, весь набор адресов проверяется fail-closed,
// после чего underlying dial получает только проверенный IP literal. Поэтому
// драйвер или ОС не могут повторно разрешить hostname уже после проверки.
type GuardedDialer struct {
	policy   Policy
	resolver Resolver
	dial     DialContextFunc
}

// NewGuardedDialer создаёт production dialer с общим TCP timeout.
func NewGuardedDialer(policy Policy, resolver Resolver, timeout time.Duration) *GuardedDialer {
	base := &net.Dialer{Timeout: timeout}
	return NewGuardedDialerWithDial(policy, resolver, base.DialContext)
}

// NewGuardedDialerWithDial позволяет детерминированно тестировать boundary,
// не открывая реальных сокетов. nil resolver означает DefaultResolver, nil
// dial — net.Dialer без дополнительного timeout (ограничение задаёт ctx).
func NewGuardedDialerWithDial(policy Policy, resolver Resolver, dial DialContextFunc) *GuardedDialer {
	if resolver == nil {
		resolver = DefaultResolver()
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return &GuardedDialer{policy: policy, resolver: resolver, dial: dial}
}

// DialContext проверяет host:port и открывает TCP-соединение только к IP из
// проверенного DNS snapshot. Ошибки не содержат hostname, IP или port.
func (d *GuardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrNotAllowed
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrNotAllowed
	}

	literal := net.ParseIP(host)
	var ips []net.IP
	if literal != nil {
		ips = []net.IP{literal}
	} else {
		lookupHost := host
		if d.policy.PrivateKubernetesDNS {
			canonical, ok := d.resolver.(interface {
				LookupCNAME(context.Context, string) (string, error)
			})
			if !ok || !IsKubernetesDNSHost(host) {
				return nil, ErrNotAllowed
			}
			// Absolute queries cannot inherit a connector Pod's DNS search path.
			lookupHost = strings.ToLower(strings.TrimSuffix(host, ".")) + "."
			name, canonicalErr := canonical.LookupCNAME(ctx, lookupHost)
			if canonicalErr != nil {
				return nil, ErrDialFailed
			}
			if !IsKubernetesDNSHost(name) {
				return nil, ErrNotAllowed
			}
		}
		ips, err = d.resolver.LookupIP(ctx, lookupHost)
		if err != nil || len(ips) == 0 {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, ErrDialFailed
		}
	}
	if err := d.policy.checkResolvedEndpoint(host, port, literal != nil, ips, nil); err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if !networkAllowsIP(network, ip) {
			continue
		}
		conn, dialErr := d.dial(ctx, network, net.JoinHostPort(ip.String(), portText))
		if dialErr == nil {
			return conn, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
	}
	return nil, ErrDialFailed
}

func networkAllowsIP(network string, ip net.IP) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return false
	}
	if network == "tcp4" {
		return ip.To4() != nil
	}
	if network == "tcp6" {
		return ip.To4() == nil
	}
	return true
}

// lookupIP резолвит host через resolver (или DefaultResolver при nil).
// Ошибка возвращается вызывающему для решения о fail-closed/best-effort.
func lookupIP(ctx context.Context, host string, resolver Resolver) ([]net.IP, error) {
	if resolver == nil {
		resolver = DefaultResolver()
	}
	return resolver.LookupIP(ctx, host)
}

// hardBlock сообщает, заблокирован ли ip жёстко, и возвращает категорию
// причины. Категория попадает в текст ошибки; сам адрес — нет.
func hardBlock(ip net.IP) (reason string, blocked bool) {
	switch {
	case ipInAny(ip, blockedMetadataCIDRs):
		return "cloud metadata", true
	case ip.IsLoopback():
		return "loopback", true
	case ip.IsLinkLocalUnicast():
		return "link-local", true
	case ip.IsUnspecified():
		return "unspecified", true
	case ip.IsMulticast():
		return "multicast", true
	default:
		return "", false
	}
}

// hostAllowlistEmpty сообщает, что host-allowlist (CIDR + DNS-суффиксы)
// пуст: тогда любой host, прошедший жёсткие блоки, разрешён.
func (p Policy) hostAllowlistEmpty() bool {
	return len(p.AllowedCIDRs) == 0 && len(p.AllowedDNSSuffixes) == 0
}

// hostAllowed проверяет host против непустого host-allowlist. DNS-суффикс
// применяется только к именам (не к литеральным IP) и не требует резолва.
// Для CIDR требуется, чтобы каждый кандидатный IP попал в разрешённую сеть:
// частично внешнее имя не считается разрешённым. Если host не резолвится
// (resolveErr != nil или пустой список), проверить CIDR нельзя — под
// активной политикой это отказ (fail-closed).
func (p Policy) hostAllowed(host string, literal bool, ips []net.IP, resolveErr error) bool {
	if !literal && p.dnsSuffixMatch(host) {
		return true
	}
	if len(p.AllowedCIDRs) == 0 {
		return false
	}
	if resolveErr != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ipInAny(ip, p.AllowedCIDRs) {
			return false
		}
	}
	return true
}

// dnsSuffixMatch сообщает, оканчивается ли host на один из разрешённых
// суффиксов (или точно равен его apex-части без ведущей точки).
func (p Policy) dnsSuffixMatch(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range p.AllowedDNSSuffixes {
		if strings.HasSuffix(h, suffix) || h == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	return false
}

// ipInAny сообщает, входит ли ip хотя бы в одну из сетей.
func ipInAny(ip net.IP, nets []net.IPNet) bool {
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// Resolver разрешает DNS-имя host в список IP. Абстракция позволяет
// подменять DNS в тестах (фейковый resolver против rebinding).
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// defaultResolver реализует Resolver поверх net.Resolver.
type defaultResolver struct {
	resolver *net.Resolver
}

// LookupIP резолвит host в IPv4 и IPv6 адреса.
func (d defaultResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return d.resolver.LookupIP(ctx, "ip", host)
}

func (d defaultResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return d.resolver.LookupCNAME(ctx, host)
}

// DefaultResolver возвращает Resolver поверх net.DefaultResolver.
func DefaultResolver() Resolver {
	return defaultResolver{resolver: net.DefaultResolver}
}
