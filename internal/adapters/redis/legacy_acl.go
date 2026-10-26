package redis

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Redis 6.2 serializes the command bitmap as categories plus individual
// commands, instead of preserving +@read/+@write -@dangerous. Compare the
// complete effective command set using that server's COMMAND metadata. Never
// normalize selectors, unknown tokens, scoped patterns or a surplus command.
func (c *adminClient) matchBundles(ctx context.Context, user aclUser) ([]string, bool, error) {
	if bundles, managed := matchBundles(user); managed {
		return bundles, true, nil
	}
	if len(user.unknown) != 0 || len(user.selectors) != 0 ||
		!slices.Equal(sortedClone(user.root.keys), []string{"~*"}) ||
		!slices.Equal(sortedClone(user.root.channels), []string{"&*"}) {
		return nil, false, nil
	}
	if !c.legacyCatalogChecked {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		server, err := c.rdb.Info(reqCtx, "server").Result()
		cancel()
		if err != nil {
			return nil, false, fmt.Errorf("read ACL server version: %w", err)
		}
		if strings.HasPrefix(parseInfo(server)["redis_version"], "6.2.") {
			reqCtx, cancel = context.WithTimeout(ctx, requestTimeout)
			commands, err := c.rdb.Command(reqCtx).Result()
			cancel()
			if err != nil {
				return nil, false, fmt.Errorf("read ACL command catalog: %w", err)
			}
			c.legacyCatalog = make(map[string][]string, len(commands))
			for name, command := range commands {
				for _, flag := range command.ACLFlags {
					c.legacyCatalog[name] = append(c.legacyCatalog[name], strings.TrimPrefix(flag, "@"))
				}
				if _, exists := c.legacyCatalog[name]; !exists {
					c.legacyCatalog[name] = nil
				}
			}
		}
		c.legacyCatalogChecked = true
	}
	bundles, managed := matchLegacyCommandSet(user.root, c.legacyCatalog)
	return bundles, managed, nil
}

func (c *adminClient) canonicalLegacyUser(ctx context.Context, user aclUser) (aclUser, error) {
	if _, managed := matchBundles(user); managed {
		return user, nil
	}
	bundles, managed, err := c.matchBundles(ctx, user)
	if err != nil || !managed {
		return user, err
	}
	rules, err := rulesFor(bundles)
	if err != nil {
		return user, err
	}
	user.root = aclSelector{}
	classifySelectorTokens(rules, &user.root, &user.unknown)
	return user, nil
}

func matchLegacyCommandSet(actual aclSelector, catalog map[string][]string) ([]string, bool) {
	if len(catalog) == 0 || !legacyRulesKnown(actual.commands, catalog) {
		return nil, false
	}
	ordinary := []string{bundleRead, bundleWrite, bundleMonitoring}
	for mask := 1; mask < 1<<len(ordinary); mask++ {
		var bundles []string
		for i, name := range ordinary {
			if mask&(1<<i) != 0 {
				bundles = append(bundles, name)
			}
		}
		// The caller fences exact full key/channel patterns. A monitoring-only
		// match would turn patterns into an unmanaged silent expansion.
		if len(bundles) == 1 && bundles[0] == bundleMonitoring {
			continue
		}
		rules, err := rulesFor(bundles)
		if err != nil {
			return nil, false
		}
		var expected aclSelector
		var unknown []string
		classifySelectorTokens(rules, &expected, &unknown)
		if !legacyRulesKnown(expected.commands, catalog) {
			return nil, false
		}
		equal := true
		for command, categories := range catalog {
			left := evalCommand(actual, command, categories)
			right := evalCommand(expected, command, categories)
			if left.full != right.full || (!left.full && !maps.Equal(left.subs, right.subs)) {
				equal = false
				break
			}
		}
		if equal {
			return bundles, true
		}
	}
	return nil, false
}

func legacyRulesKnown(rules []string, catalog map[string][]string) bool {
	categories := map[string]bool{"all": true}
	for _, values := range catalog {
		for _, value := range values {
			categories[value] = true
		}
	}
	for _, rule := range rules {
		if len(rule) < 2 {
			return false
		}
		if category, ok := strings.CutPrefix(rule[1:], "@"); ok {
			if !categories[category] {
				return false
			}
			continue
		}
		name, _, subcommand := strings.Cut(rule[1:], "|")
		if _, known := catalog[name]; !known || (subcommand && rule[0] == '-') {
			return false
		}
	}
	return true
}
