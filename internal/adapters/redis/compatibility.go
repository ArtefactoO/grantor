package redis

import (
	"context"
	"fmt"
)

// Redis accepts multiple INFO sections only since 7.0. Single-section reads
// retain the same metadata scope on both 6.2 and 7 without retrying errors.
func (c *adminClient) serverAndReplicationInfo(ctx context.Context) (map[string]string, error) {
	return readServerAndReplicationInfo(ctx, func(reqCtx context.Context, section string) (string, error) {
		return c.rdb.Info(reqCtx, section).Result()
	})
}

func readServerAndReplicationInfo(ctx context.Context,
	read func(context.Context, string) (string, error),
) (map[string]string, error) {
	info := make(map[string]string)
	for _, section := range []string{"server", "replication"} {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		text, err := read(reqCtx, section)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("read %s info: %w", section, err)
		}
		for key, value := range parseInfo(text) {
			info[key] = value
		}
	}
	return info, nil
}

// This is configuration metadata, not proof of a successful ACL SAVE or of
// durable storage. Inaccessible CONFIG must remain unknown, never absent.
func (c *adminClient) aclPersistence(ctx context.Context) string {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	config, err := c.rdb.ConfigGet(reqCtx, "aclfile").Result()
	return aclPersistenceStatus(config, err)
}

func aclPersistenceStatus(config map[string]string, err error) string {
	if err != nil {
		return "unknown"
	}
	path, known := config["aclfile"]
	if !known {
		return "unknown"
	}
	if path == "" {
		return "runtime_only"
	}
	return "configured"
}
