package jobs

import (
	"testing"
	"time"

	"github.com/riverqueue/river"
)

func TestOperationArgsKind(t *testing.T) {
	if got := (OperationArgs{}).Kind(); got != "operation.execute" {
		t.Errorf("OperationArgs.Kind() = %q, want %q", got, "operation.execute")
	}
}

func TestConfigWithDefaults(t *testing.T) {
	t.Run("zero value gets all defaults", func(t *testing.T) {
		got := Config{}.withDefaults()
		want := Config{
			Queue:        river.QueueDefault,
			WorkerCount:  4,
			MaxAttempts:  5,
			JobTimeout:   5 * time.Minute,
			SnoozeOnLock: 5 * time.Second,
		}
		if got != want {
			t.Errorf("Config{}.withDefaults() = %+v, want %+v", got, want)
		}
	})

	t.Run("explicit values are preserved", func(t *testing.T) {
		in := Config{
			Queue:        "custom",
			WorkerCount:  2,
			MaxAttempts:  1,
			JobTimeout:   time.Second,
			SnoozeOnLock: time.Millisecond,
		}
		if got := in.withDefaults(); got != in {
			t.Errorf("withDefaults() = %+v, want unchanged %+v", got, in)
		}
	})

	t.Run("partial config keeps set fields and fills the rest", func(t *testing.T) {
		got := Config{Queue: "ops", MaxAttempts: 10}.withDefaults()
		want := Config{
			Queue:        "ops",
			WorkerCount:  4,
			MaxAttempts:  10,
			JobTimeout:   5 * time.Minute,
			SnoozeOnLock: 5 * time.Second,
		}
		if got != want {
			t.Errorf("withDefaults() = %+v, want %+v", got, want)
		}
	})

	t.Run("negative values are replaced with defaults", func(t *testing.T) {
		got := Config{WorkerCount: -1, MaxAttempts: -1, JobTimeout: -time.Second, SnoozeOnLock: -time.Second}.withDefaults()
		want := Config{}.withDefaults()
		if got != want {
			t.Errorf("withDefaults() = %+v, want %+v", got, want)
		}
	})
}

// Хвост последовательности обязан отменяться на любом окончательном исходе.
// Регрессия: когда детерминированные отказы стали терминальными, отмена
// осталась под условием «исчерпаны попытки» — а терминальная ошибка до него
// не доходит. Дочерние операции зависали в pending, bulk-родитель в running,
// и починить это через API было нельзя.
func TestShouldCancelDependents(t *testing.T) {
	cases := []struct {
		name        string
		terminal    bool
		attempt     int
		maxAttempts int
		want        bool
	}{
		{name: "терминальный отказ на первой попытке", terminal: true, attempt: 1, maxAttempts: 5, want: true},
		{name: "попытки исчерпаны", terminal: false, attempt: 5, maxAttempts: 5, want: true},
		{name: "терминальный и попытки исчерпаны", terminal: true, attempt: 5, maxAttempts: 5, want: true},
		// Ретраибельная ошибка с оставшимися попытками хвост не трогает:
		// следующая попытка может пройти, и отменять зависимые рано.
		{name: "ретраибельный отказ, попытки остались", terminal: false, attempt: 1, maxAttempts: 5, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldCancelDependents(tc.terminal, tc.attempt, tc.maxAttempts); got != tc.want {
				t.Errorf("shouldCancelDependents(%v, %d, %d) = %v, want %v",
					tc.terminal, tc.attempt, tc.maxAttempts, got, tc.want)
			}
		})
	}
}
