package redis

import (
	"context"
	"errors"
	"testing"
)

func TestRequireACLSaveUsesFreshContextForEveryCommand(t *testing.T) {
	calls := 0
	checkContext := func(ctx context.Context) error {
		calls++
		if err := ctx.Err(); err != nil {
			return errors.New("command received an already-cancelled context")
		}
		return nil
	}
	err := requireACLSaveWithCommands(t.Context(), "redis:run:test-run",
		func(ctx context.Context) (string, error) {
			return "run_id:test-run\r\n", checkContext(ctx)
		},
		func(ctx context.Context) (map[string]string, error) {
			return map[string]string{"aclfile": "/data/users.acl"}, checkContext(ctx)
		},
		func(ctx context.Context) error {
			return checkContext(ctx)
		},
	)
	if err != nil {
		t.Fatalf("requireACLSaveWithCommands: %v", err)
	}
	if calls != 3 {
		t.Fatalf("commands called %d times, want 3", calls)
	}
}
