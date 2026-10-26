package redis

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestReadServerAndReplicationInfoUsesSingleSectionContexts(t *testing.T) {
	var sections []string
	var previous context.Context
	info, err := readServerAndReplicationInfo(t.Context(), func(ctx context.Context, section string) (string, error) {
		if ctx.Err() != nil {
			t.Fatal("each section must receive a live context")
		}
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("INFO command must have a timeout")
		}
		if previous != nil && previous.Err() == nil {
			t.Fatal("previous command context must have been cancelled")
		}
		previous = ctx
		sections = append(sections, section)
		switch section {
		case "server":
			return "# Server\r\nredis_version:6.2.12\r\nredis_mode:standalone\r\nrun_id:test-run\r\n", nil
		case "replication":
			return "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n", nil
		default:
			t.Fatalf("unexpected INFO section %q", section)
			return "", nil
		}
	})
	if err != nil {
		t.Fatalf("read info: %v", err)
	}
	if !slices.Equal(sections, []string{"server", "replication"}) || info["redis_version"] != "6.2.12" ||
		info["run_id"] != "test-run" || info["role"] != "master" {
		t.Fatalf("sections=%v metadata=%v", sections, info)
	}
	if previous.Err() == nil {
		t.Fatal("last command context must have been cancelled")
	}
}

func TestReadServerAndReplicationInfoDoesNotTurnFailureIntoTopology(t *testing.T) {
	for _, failed := range []string{"server", "replication"} {
		t.Run(failed, func(t *testing.T) {
			cause := errors.New("target unavailable")
			calls := 0
			info, err := readServerAndReplicationInfo(t.Context(), func(_ context.Context, section string) (string, error) {
				calls++
				if section == failed {
					return "", cause
				}
				return "redis_version:6.2.12\r\n", nil
			})
			if !errors.Is(err, cause) || info != nil {
				t.Fatalf("metadata=%v error=%v; want no partial topology and retained cause", info, err)
			}
			if failed == "server" && calls != 1 {
				t.Fatal("do not retry a failed INFO or read further sections")
			}
		})
	}
}

func TestACLPersistenceStatusDistinguishesMissingFromUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]string
		err    error
		want   string
	}{
		{"runtime only", map[string]string{"aclfile": ""}, nil, "runtime_only"},
		{"configured does not mean saved", map[string]string{"aclfile": "/data/users.acl"}, nil, "configured"},
		{"unreadable", nil, errors.New("NOPERM"), "unknown"},
		{"unavailable", nil, context.DeadlineExceeded, "unknown"},
		{"missing response field", map[string]string{}, nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := aclPersistenceStatus(tc.config, tc.err); got != tc.want {
				t.Fatalf("status=%q want %q", got, tc.want)
			}
		})
	}
}
