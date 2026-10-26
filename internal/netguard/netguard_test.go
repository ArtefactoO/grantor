package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// fakeResolver — детерминированный Resolver для тестов: сопоставляет host
// заранее заданным IP (или ошибке при отсутствии записи).
type fakeResolver map[string][]net.IP

func (f fakeResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := f[host]
	if !ok {
		return nil, fmt.Errorf("fakeResolver: no such host %q", host)
	}
	return ips, nil
}

type sequenceResolver struct {
	answers [][]net.IP
	calls   int
}

func (r *sequenceResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	idx := r.calls
	r.calls++
	if idx >= len(r.answers) {
		return nil, errors.New("unexpected lookup")
	}
	return r.answers[idx], nil
}

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy(
		[]string{"10.0.0.0/8", " ", "192.168.0.0/16"},
		[]string{"5432", "", "27017"},
		[]string{"Internal.Example.com", ".db.local", ""},
	)
	if err != nil {
		t.Fatalf("ParsePolicy: unexpected error: %v", err)
	}
	if len(p.AllowedCIDRs) != 2 {
		t.Errorf("AllowedCIDRs = %d, want 2", len(p.AllowedCIDRs))
	}
	if len(p.AllowedPorts) != 2 || p.AllowedPorts[0] != 5432 || p.AllowedPorts[1] != 27017 {
		t.Errorf("AllowedPorts = %v, want [5432 27017]", p.AllowedPorts)
	}
	wantSuffixes := []string{".internal.example.com", ".db.local"}
	if len(p.AllowedDNSSuffixes) != len(wantSuffixes) {
		t.Fatalf("AllowedDNSSuffixes = %v, want %v", p.AllowedDNSSuffixes, wantSuffixes)
	}
	for i, s := range wantSuffixes {
		if p.AllowedDNSSuffixes[i] != s {
			t.Errorf("AllowedDNSSuffixes[%d] = %q, want %q", i, p.AllowedDNSSuffixes[i], s)
		}
	}

	invalid := []struct {
		name                   string
		cidrs, ports, suffixes []string
	}{
		{"bad cidr", []string{"not-a-cidr"}, nil, nil},
		{"bad port", nil, []string{"abc"}, nil},
		{"port zero", nil, []string{"0"}, nil},
		{"port too large", nil, []string{"70000"}, nil},
	}
	for _, tc := range invalid {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			if _, err := ParsePolicy(tc.cidrs, tc.ports, tc.suffixes); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// emptyPolicy — политика без allowlist: только жёсткие блоки.
func emptyPolicy() Policy { return Policy{} }

func TestCheckEndpointHardBlocksLiteral(t *testing.T) {
	blocked := []struct {
		name string
		host string
	}{
		{"aws metadata", "169.254.169.254"},
		{"aws metadata ipv6", "fd00:ec2::254"},
		{"alibaba metadata", "100.100.100.100"},
		{"loopback v4", "127.0.0.1"},
		{"loopback v4 range", "127.10.20.30"},
		{"loopback v6", "::1"},
		{"link-local v4", "169.254.10.20"},
		{"link-local v6", "fe80::1"},
		{"unspecified v4", "0.0.0.0"},
		{"unspecified v6", "::"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
	}
	p := emptyPolicy()
	for _, tc := range blocked {
		t.Run(tc.name, func(t *testing.T) {
			err := p.CheckEndpoint(t.Context(), tc.host, 5432, nil)
			if !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("CheckEndpoint(%q) error = %v, want ErrBlockedAddress", tc.host, err)
			}
			// Причина не должна раскрывать сам адрес.
			if err != nil && strings.Contains(err.Error(), tc.host) {
				t.Errorf("error %q leaks the address %q", err, tc.host)
			}
		})
	}
}

func TestCheckEndpointEmptyPolicyAllowsPublicAndPrivate(t *testing.T) {
	// ВАЖНО: приватные диапазоны НЕ блокируются — grantor подключается к
	// приватным БД. Публичные адреса при пустой политике тоже разрешены.
	allowed := []struct {
		name string
		host string
	}{
		{"public v4", "8.8.8.8"},
		{"public v4 cloudflare", "1.1.1.1"},
		{"private class A", "10.1.2.3"},
		{"private class C", "192.168.10.20"},
		{"private class B", "172.16.5.5"},
		{"public v6", "2606:4700:4700::1111"},
		{"ula v6 not metadata", "fd12:3456:789a::1"},
	}
	p := emptyPolicy()
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.CheckEndpoint(t.Context(), tc.host, 5432, nil); err != nil {
				t.Fatalf("CheckEndpoint(%q) = %v, want nil", tc.host, err)
			}
		})
	}
}

// target-postgres-подобный приватный host, резолвящийся в приватный IP,
// при пустой политике разрешён.
func TestCheckEndpointPrivateHostnameAllowed(t *testing.T) {
	res := fakeResolver{"target-postgres": {net.ParseIP("10.20.30.40")}}
	if err := emptyPolicy().CheckEndpoint(t.Context(), "target-postgres", 5432, res); err != nil {
		t.Fatalf("CheckEndpoint(target-postgres) = %v, want nil", err)
	}
}

func TestCheckEndpointAllowlistCIDR(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{AllowedCIDRs: []net.IPNet{*cidr}}

	// В allowlist — проходит.
	if err := p.CheckEndpoint(t.Context(), "10.1.2.3", 5432, nil); err != nil {
		t.Errorf("CheckEndpoint(10.1.2.3) = %v, want nil", err)
	}
	// Вне allowlist (публичный) — отказ, хотя жёсткого блока нет.
	err = p.CheckEndpoint(t.Context(), "8.8.8.8", 5432, nil)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("CheckEndpoint(8.8.8.8) error = %v, want ErrNotAllowed", err)
	}
	// Вне allowlist приватный (другой диапазон) — тоже отказ.
	err = p.CheckEndpoint(t.Context(), "192.168.1.1", 5432, nil)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("CheckEndpoint(192.168.1.1) error = %v, want ErrNotAllowed", err)
	}
}

func TestCheckEndpointPorts(t *testing.T) {
	p := Policy{AllowedPorts: []int{5432, 27017}}

	if err := p.CheckEndpoint(t.Context(), "10.1.2.3", 5432, nil); err != nil {
		t.Errorf("port 5432 = %v, want nil", err)
	}
	err := p.CheckEndpoint(t.Context(), "10.1.2.3", 6379, nil)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("port 6379 error = %v, want ErrNotAllowed", err)
	}
	// Неуказанный порт (0) при заданном списке портов — отказ.
	err = p.CheckEndpoint(t.Context(), "10.1.2.3", 0, nil)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("port 0 error = %v, want ErrNotAllowed", err)
	}
}

func TestCheckEndpointDNSSuffix(t *testing.T) {
	res := fakeResolver{
		"db.internal.example.com": {net.ParseIP("203.0.113.10")},
		"internal.example.com":    {net.ParseIP("203.0.113.11")},
		"db.other.example.com":    {net.ParseIP("203.0.113.12")},
	}
	p := Policy{AllowedDNSSuffixes: []string{".internal.example.com"}}

	// Совпадение по суффиксу — проходит, несмотря на публичный резолв
	// (host-allowlist проверяет имя, жёсткий блок публичный IP не трогает).
	if err := p.CheckEndpoint(t.Context(), "db.internal.example.com", 5432, res); err != nil {
		t.Errorf("suffix match = %v, want nil", err)
	}
	// Точное совпадение apex без ведущей точки — проходит.
	if err := p.CheckEndpoint(t.Context(), "internal.example.com", 5432, res); err != nil {
		t.Errorf("apex match = %v, want nil", err)
	}
	// Другой суффикс — отказ.
	err := p.CheckEndpoint(t.Context(), "db.other.example.com", 5432, res)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("non-matching suffix error = %v, want ErrNotAllowed", err)
	}
}

func TestCheckEndpointResolverRebinding(t *testing.T) {
	// Host резолвится в два адреса: один валидный публичный, второй —
	// cloud-metadata. Проверка КАЖДОГО IP должна дать отказ (rebinding).
	res := fakeResolver{
		"evil.example.com": {
			net.ParseIP("203.0.113.5"),
			net.ParseIP("169.254.169.254"),
		},
	}
	err := emptyPolicy().CheckEndpoint(t.Context(), "evil.example.com", 5432, res)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("rebinding error = %v, want ErrBlockedAddress", err)
	}

	// Резолв в единственный metadata-адрес — тоже блок.
	res2 := fakeResolver{"meta.example.com": {net.ParseIP("169.254.169.254")}}
	err = emptyPolicy().CheckEndpoint(t.Context(), "meta.example.com", 5432, res2)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("single metadata resolve error = %v, want ErrBlockedAddress", err)
	}
}

func TestGuardedDialerPinsCheckedDNSAnswer(t *testing.T) {
	// Второй ответ имитирует rebinding после предварительной проверки.
	// GuardedDialer обязан сделать один lookup и передать underlying dial
	// числовой IP из проверенного snapshot, а не исходный hostname.
	resolver := &sequenceResolver{answers: [][]net.IP{
		{net.ParseIP("203.0.113.10")},
		{net.ParseIP("169.254.169.254")},
	}}
	var dialed string
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	dialer := NewGuardedDialerWithDial(Policy{}, resolver,
		func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q, want tcp", network)
			}
			dialed = address
			return client, nil
		})

	conn, err := dialer.DialContext(t.Context(), "tcp", "db.example.com:5432")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	if resolver.calls != 1 {
		t.Fatalf("DNS lookups = %d, want exactly 1", resolver.calls)
	}
	if dialed != "203.0.113.10:5432" {
		t.Fatalf("underlying dial address = %q, want checked IP literal", dialed)
	}
}

func TestGuardedDialerRejectsMixedDNSBeforeDial(t *testing.T) {
	resolver := fakeResolver{"db.example.com": {
		net.ParseIP("203.0.113.10"),
		net.ParseIP("169.254.169.254"),
	}}
	dialCalls := 0
	dialer := NewGuardedDialerWithDial(Policy{}, resolver,
		func(context.Context, string, string) (net.Conn, error) {
			dialCalls++
			return nil, errors.New("must not dial")
		})

	_, err := dialer.DialContext(t.Context(), "tcp", "db.example.com:5432")
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("DialContext error = %v, want ErrBlockedAddress", err)
	}
	if dialCalls != 0 {
		t.Fatalf("underlying dial calls = %d, want 0", dialCalls)
	}
	if strings.Contains(err.Error(), "db.example.com") || strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("DialContext error leaks endpoint: %v", err)
	}
}

func TestCheckEndpointResolveFailureBestEffort(t *testing.T) {
	res := fakeResolver{} // host не резолвится

	// Пустая политика: непроверяемый host разрешён (best-effort; строгая
	// проверка IP — на dial-time). Иначе создание connection зависело бы от
	// доступности DNS целевой БД из API.
	if err := emptyPolicy().CheckEndpoint(t.Context(), "unknown.example.com", 5432, res); err != nil {
		t.Errorf("empty policy resolve failure = %v, want nil", err)
	}

	// Активная CIDR-политика: нерезолвящийся host без совпадения по суффиксу
	// — отказ (fail-closed под политикой).
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	cidrPolicy := Policy{AllowedCIDRs: []net.IPNet{*cidr}}
	if err := cidrPolicy.CheckEndpoint(t.Context(), "unknown.example.com", 5432, res); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("cidr policy resolve failure = %v, want ErrNotAllowed", err)
	}

	// Политика по суффиксу: совпадение по имени не требует резолва.
	suffixPolicy := Policy{AllowedDNSSuffixes: []string{".example.com"}}
	if err := suffixPolicy.CheckEndpoint(t.Context(), "unknown.example.com", 5432, res); err != nil {
		t.Errorf("suffix policy match despite resolve failure = %v, want nil", err)
	}
}

func TestCheckEndpointCIDRHostnameAllResolvedMustMatch(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{AllowedCIDRs: []net.IPNet{*cidr}}

	// Все резолвленные IP в CIDR — проходит.
	inRange := fakeResolver{"db": {net.ParseIP("10.1.1.1"), net.ParseIP("10.2.2.2")}}
	if err := p.CheckEndpoint(t.Context(), "db", 5432, inRange); err != nil {
		t.Errorf("all-in-range = %v, want nil", err)
	}
	// Хотя бы один IP вне CIDR — отказ (частично внешнее имя).
	mixed := fakeResolver{"db2": {net.ParseIP("10.1.1.1"), net.ParseIP("8.8.8.8")}}
	err = p.CheckEndpoint(t.Context(), "db2", 5432, mixed)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("partially external error = %v, want ErrNotAllowed", err)
	}
}

func TestCheckEndpointIPv6Allowlist(t *testing.T) {
	_, cidr, err := net.ParseCIDR("fd00:cafe::/32")
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{AllowedCIDRs: []net.IPNet{*cidr}}

	if err := p.CheckEndpoint(t.Context(), "fd00:cafe::5", 5432, nil); err != nil {
		t.Errorf("in-range IPv6 = %v, want nil", err)
	}
	err = p.CheckEndpoint(t.Context(), "2606:4700:4700::1111", 5432, nil)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("out-of-range IPv6 error = %v, want ErrNotAllowed", err)
	}
}
