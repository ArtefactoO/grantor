package ratelimit

import (
	"testing"
	"time"
)

func TestKeyBuilders(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"login", LoginKey("1.2.3.4"), "login:1.2.3.4"},
		{"reveal", RevealKey("sub-123"), "reveal:sub-123"},
		{"mutating", MutatingKey("sub-123"), "mutating:sub-123"},
		{"login empty", LoginKey(""), "login:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("key = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestRetryAfterDuration(t *testing.T) {
	cases := []struct {
		name      string
		available float64
		rate      float64
		want      time.Duration
	}{
		{"empty bucket slow rate", 0, 0.2, 5 * time.Second},
		{"half token", 0.5, 0.5, time.Second},
		{"almost full", 0.9, 1, 100 * time.Millisecond},
		{"available >= 1 gives zero", 1, 1, 0},
		{"zero rate gives zero", 0, 0, 0},
		{"negative rate gives zero", 0, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := retryAfterDuration(tc.available, tc.rate)
			// Дробная арифметика: сверяем с допуском в 1 мс.
			if diff := got - tc.want; diff < -time.Millisecond || diff > time.Millisecond {
				t.Errorf("retryAfterDuration(%v, %v) = %v, want %v", tc.available, tc.rate, got, tc.want)
			}
		})
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want int
	}{
		{"zero", 0, 0},
		{"negative", -time.Second, 0},
		{"exact second", time.Second, 1},
		{"rounds up sub-second", 200 * time.Millisecond, 1},
		{"rounds up fractional", 1200 * time.Millisecond, 2},
		{"rounds up 4.5s", 4500 * time.Millisecond, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RetryAfterSeconds(tc.in); got != tc.want {
				t.Errorf("RetryAfterSeconds(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
