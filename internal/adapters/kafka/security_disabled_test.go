package kafka

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestPermissionCatalogWithoutAuthorizerIsReadOnly(t *testing.T) {
	for _, assignable := range []bool{true, false} {
		permissions := append(topicPermissions("orders", assignable), clusterAdminPermissionDef(assignable))
		if len(permissions) != 3 {
			t.Fatal("authorizer state must not erase the topic permission catalog")
		}
		for _, permission := range permissions {
			if permission.Assignable != assignable {
				t.Errorf("permission %s assignable=%t, want %t", permission.ExternalID, permission.Assignable, assignable)
			}
			if permission.ExternalID != clusterAdminPermission && permission.ScopeExternalID != "topic:orders" {
				t.Error("authorizer state must preserve the topic scope")
			}
		}
	}
}

// stubDescribeACLs подменяет DescribeAcls целевого кластера фиксированным
// ответом — так путь SECURITY_DISABLED проверяется без живого брокера.
func stubDescribeACLs(results kadm.DescribeACLsResults, err error) func(context.Context, *kadm.ACLBuilder) (kadm.DescribeACLsResults, error) {
	return func(context.Context, *kadm.ACLBuilder) (kadm.DescribeACLsResults, error) {
		return results, err
	}
}

// plainClientWithACLs собирает adminClient с не-SCRAM (plain) auth и
// подменённым DescribeAcls. adm/kcl остаются nil: пути, отклоняющие ACL-мутацию,
// возвращают управление до любого обращения к реальному клиенту.
func plainClientWithACLs(fn func(context.Context, *kadm.ACLBuilder) (kadm.DescribeACLsResults, error)) *adminClient {
	return &adminClient{
		auth:           authConfig{mechanism: mechPlain, protocol: protoSASLPlaintext},
		describeACLsFn: fn,
	}
}

// TestIsSecurityDisabled проверяет распознавание SECURITY_DISABLED по
// типизированному значению kerr (code 54), а не по тексту сообщения, и на
// «голой», и на завёрнутой (%w) ошибке — так kadm отдаёт per-result ошибку.
func TestIsSecurityDisabled(t *testing.T) {
	if !isSecurityDisabled(kerr.SecurityDisabled) {
		t.Error("bare kerr.SecurityDisabled must be detected")
	}
	if kerr.SecurityDisabled.Code != 54 {
		t.Errorf("kerr.SecurityDisabled.Code = %d, want 54", kerr.SecurityDisabled.Code)
	}
	// kadm заворачивает per-result ошибку фильтра в цепочку %w.
	if !isSecurityDisabled(fmt.Errorf("describe acls filter: %w", kerr.SecurityDisabled)) {
		t.Error("wrapped SECURITY_DISABLED must be detected")
	}
	// Тот же код, полученный через ErrorForCode(54) (как это делает kadm).
	if !isSecurityDisabled(kerr.ErrorForCode(54)) {
		t.Error("SECURITY_DISABLED via ErrorForCode(54) must be detected")
	}

	if isSecurityDisabled(nil) {
		t.Error("nil must not be SECURITY_DISABLED")
	}
	if isSecurityDisabled(kerr.ClusterAuthorizationFailed) {
		t.Error("CLUSTER_AUTHORIZATION_FAILED must not be SECURITY_DISABLED")
	}
	// Детекция не по тексту: та же фраза в обычной ошибке не считается.
	if isSecurityDisabled(errors.New("Security features are disabled.")) {
		t.Error("detection must be by kerr value, not by message text")
	}
}

// TestAclAdminUnavailable проверяет, что выключенный authorizer превращается в
// adapter.ErrUnsupportedChange, а нехватка прав (CLUSTER_AUTHORIZATION_FAILED) и
// nil — нет.
func TestAclAdminUnavailable(t *testing.T) {
	err := aclAdminUnavailable("access.grant", fmt.Errorf("describe acls filter: %w", kerr.SecurityDisabled))
	if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Fatalf("err = %v, want adapter.ErrUnsupportedChange", err)
	}
	if !strings.Contains(err.Error(), "authorizer disabled") {
		t.Errorf("message = %q, want it to mention authorizer disabled", err.Error())
	}
	if !strings.Contains(err.Error(), "access.grant") {
		t.Errorf("message = %q, want it to name the operation", err.Error())
	}

	authFail := aclAdminUnavailable("access.grant", kerr.ClusterAuthorizationFailed)
	if errors.Is(authFail, adapter.ErrUnsupportedChange) {
		t.Error("CLUSTER_AUTHORIZATION_FAILED must not become ErrUnsupportedChange (it is a privilege problem)")
	}
	if !errors.Is(authFail, kerr.ClusterAuthorizationFailed) {
		t.Error("non-security-disabled error must pass through unchanged")
	}

	if aclAdminUnavailable("access.grant", nil) != nil {
		t.Error("nil error must pass through as nil")
	}
}

// TestDescribeACLsTolerant проверяет толерантность к выключенному authorizer на
// обоих уровнях ответа DescribeAcls (per-result и whole-request), проброс
// нехватки прав и нормальный разбор записей.
func TestDescribeACLsTolerant(t *testing.T) {
	ctx := t.Context()

	t.Run("result-level SECURITY_DISABLED tolerated", func(t *testing.T) {
		c := plainClientWithACLs(stubDescribeACLs(kadm.DescribeACLsResults{{Err: kerr.SecurityDisabled}}, nil))
		entries, disabled, err := c.describeACLsTolerant(ctx)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if !disabled {
			t.Error("aclAdminDisabled = false, want true")
		}
		if len(entries) != 0 {
			t.Errorf("entries = %v, want empty", entries)
		}
	})

	t.Run("request-level SECURITY_DISABLED tolerated", func(t *testing.T) {
		c := plainClientWithACLs(stubDescribeACLs(nil, kerr.SecurityDisabled))
		_, disabled, err := c.describeACLsTolerant(ctx)
		if err != nil || !disabled {
			t.Fatalf("got (disabled=%v, err=%v), want (true, nil)", disabled, err)
		}
	})

	t.Run("CLUSTER_AUTHORIZATION_FAILED propagates as error", func(t *testing.T) {
		c := plainClientWithACLs(stubDescribeACLs(kadm.DescribeACLsResults{{Err: kerr.ClusterAuthorizationFailed}}, nil))
		_, disabled, err := c.describeACLsTolerant(ctx)
		if disabled {
			t.Error("aclAdminDisabled = true, want false for a privilege failure")
		}
		if !errors.Is(err, kerr.ClusterAuthorizationFailed) {
			t.Errorf("err = %v, want CLUSTER_AUTHORIZATION_FAILED", err)
		}
	})

	t.Run("normal ACLs are returned", func(t *testing.T) {
		described := kadm.DescribedACL{
			Principal:  "User:svc",
			Host:       "*",
			Type:       kmsg.ACLResourceTypeTopic,
			Name:       "orders",
			Pattern:    kadm.ACLPatternLiteral,
			Operation:  kadm.OpWrite,
			Permission: kmsg.ACLPermissionTypeAllow,
		}
		c := plainClientWithACLs(stubDescribeACLs(kadm.DescribeACLsResults{{Described: kadm.DescribedACLs{described}}}, nil))
		entries, disabled, err := c.describeACLsTolerant(ctx)
		if err != nil || disabled {
			t.Fatalf("got (disabled=%v, err=%v), want (false, nil)", disabled, err)
		}
		want := allowLiteral("svc", kmsg.ACLResourceTypeTopic, "orders", kadm.OpWrite)
		if len(entries) != 1 || entries[0] != want {
			t.Errorf("entries = %v, want single produce WRITE entry %v", entries, want)
		}
	})
}

// TestPrincipalACLsTolerant проверяет, что при выключенном authorizer чтение
// ACL principal даёт пустой набор (у кластера ACL нет), а прочие ошибки
// пробрасываются.
func TestPrincipalACLsTolerant(t *testing.T) {
	ctx := t.Context()

	c := plainClientWithACLs(stubDescribeACLs(kadm.DescribeACLsResults{{Err: kerr.SecurityDisabled}}, nil))
	entries, err := c.principalACLsTolerant(ctx, "svc")
	if err != nil {
		t.Fatalf("err = %v, want nil (authz off -> no acls)", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want empty", entries)
	}

	c2 := plainClientWithACLs(stubDescribeACLs(kadm.DescribeACLsResults{{Err: kerr.ClusterAuthorizationFailed}}, nil))
	if _, err := c2.principalACLsTolerant(ctx, "svc"); !errors.Is(err, kerr.ClusterAuthorizationFailed) {
		t.Errorf("err = %v, want CLUSTER_AUTHORIZATION_FAILED propagated", err)
	}
}

// TestApplyACLMutationsRejectedWhenAuthorizerDisabled проверяет, что при
// выключенном authorizer все ACL-мутации (grant/revoke и disable/enable через
// DENY-маркеры) отклоняются до любой мутации как adapter.ErrUnsupportedChange с
// понятным сообщением. adm клиента nil — если бы шаг дошёл до CreateAcls/
// DeleteAcls, тест упал бы паникой; отклонение происходит раньше.
func TestApplyACLMutationsRejectedWhenAuthorizerDisabled(t *testing.T) {
	ctx := t.Context()
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}
	secDisabled := stubDescribeACLs(kadm.DescribeACLsResults{{Err: kerr.SecurityDisabled}}, nil)

	cases := []struct {
		name   string
		change adapter.DesiredChange
		apply  func(context.Context, *adminClient, adapter.DesiredChange) (adapter.StepStatus, error)
	}{
		{"grant", adapter.DesiredChange{Kind: adapter.ChangeGrant, Account: acct, Permission: "topic-produce:orders"}, applyGrant},
		{"revoke", adapter.DesiredChange{Kind: adapter.ChangeRevoke, Account: acct, Permission: "topic-produce:orders"}, applyRevoke},
		{"disable", adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Account: acct}, applyDisableUser},
		{"enable", adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Account: acct}, applyEnableUser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := plainClientWithACLs(secDisabled)
			status, err := tc.apply(ctx, c, tc.change)
			if status != adapter.StepFailed {
				t.Errorf("status = %v, want StepFailed", status)
			}
			if !errors.Is(err, adapter.ErrUnsupportedChange) {
				t.Fatalf("err = %v, want adapter.ErrUnsupportedChange", err)
			}
			if !strings.Contains(err.Error(), "authorizer disabled") {
				t.Errorf("message = %q, want it to mention authorizer disabled", err.Error())
			}
		})
	}
}
