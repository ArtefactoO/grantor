package inventory

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestResolveBindingStatus(t *testing.T) {
	present := BindingPresent
	absent := BindingAbsent

	tests := []struct {
		name     string
		desired  *BindingState
		observed BindingState
		current  BindingStatus
		want     BindingStatus
	}{
		// Непринятое право — наблюдение, а не ожидание применения: применять
		// его никто не собирается, пока оператор не принял решение.
		{
			name:     "unmanaged present is observed",
			desired:  nil,
			observed: BindingPresent,
			current:  BindingStatusPending,
			want:     BindingStatusObserved,
		},
		{
			name:     "unmanaged absent is observed",
			desired:  nil,
			observed: BindingAbsent,
			current:  BindingStatusPending,
			want:     BindingStatusObserved,
		},
		{
			name:     "unmanaged overrides any previous status",
			desired:  nil,
			observed: BindingPresent,
			current:  BindingStatusDrift,
			want:     BindingStatusObserved,
		},
		{
			name:     "desired present observed present is synced",
			desired:  &present,
			observed: BindingPresent,
			current:  BindingStatusPending,
			want:     BindingStatusSynced,
		},
		{
			name:     "desired present observed absent is drift",
			desired:  &present,
			observed: BindingAbsent,
			current:  BindingStatusSynced,
			want:     BindingStatusDrift,
		},
		{
			name:     "desired absent observed present is drift",
			desired:  &absent,
			observed: BindingPresent,
			current:  BindingStatusPending,
			want:     BindingStatusDrift,
		},
		{
			name:     "desired absent observed absent is synced",
			desired:  &absent,
			observed: BindingAbsent,
			current:  BindingStatusPending,
			want:     BindingStatusSynced,
		},
		{
			name:     "observed unknown keeps current",
			desired:  &present,
			observed: BindingUnknown,
			current:  BindingStatusFailed,
			want:     BindingStatusFailed,
		},
		{
			name:     "match overrides previous failed",
			desired:  &present,
			observed: BindingPresent,
			current:  BindingStatusFailed,
			want:     BindingStatusSynced,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Признак действенности здесь всегда true: этот тест про соотношение
			// desired и observed, недействующее право проверяет
			// TestResolveBindingStatusIneffective.
			if got := ResolveBindingStatus(tt.desired, tt.observed, true, tt.current); got != tt.want {
				t.Errorf("ResolveBindingStatus(%v, %q, %q) = %q, want %q",
					tt.desired, tt.observed, tt.current, got, tt.want)
			}
		})
	}
}

func TestCheckAccountLifecycle(t *testing.T) {
	account := Account{ID: uuid.New(), Status: AccountDeleted, LifecycleVersion: 3}
	if err := CheckAccountLifecycle(account, AccountDeleted, 3); err != nil {
		t.Fatalf("matching lifecycle: %v", err)
	}
	if err := CheckAccountLifecycle(account, "", 3); err != nil {
		t.Fatalf("matching version without status guard: %v", err)
	}
	if err := CheckAccountLifecycle(account, AccountActive, 3); !errors.Is(err, ErrAccountStatusConflict) {
		t.Fatalf("status mismatch error = %v, want ErrAccountStatusConflict", err)
	}
	if err := CheckAccountLifecycle(account, AccountDeleted, 2); !errors.Is(err, ErrAccountLifecycleConflict) {
		t.Fatalf("version mismatch error = %v, want ErrAccountLifecycleConflict", err)
	}
}

// Право, которое существует, но не действует, синхронизированным не является.
// Регрессия аудита: MySQL и ClickHouse отдавали роль вне набора по умолчанию
// как present, ядро признак теряло, binding получал synced — а пользователь
// получал отказ в доступе.
func TestResolveBindingStatusIneffective(t *testing.T) {
	present := BindingPresent
	absent := BindingAbsent

	cases := []struct {
		name      string
		desired   *BindingState
		observed  BindingState
		effective bool
		current   BindingStatus
		want      BindingStatus
	}{
		{name: "выдано и действует", desired: &present, observed: BindingPresent,
			effective: true, current: BindingStatusPending, want: BindingStatusSynced},
		{name: "выдано, но не действует", desired: &present, observed: BindingPresent,
			effective: false, current: BindingStatusSynced, want: BindingStatusDrift},
		{name: "снято и отсутствует", desired: &absent, observed: BindingAbsent,
			effective: true, current: BindingStatusPending, want: BindingStatusSynced},
		// Признак действенности не имеет смысла для отсутствующего права и
		// не должен превращать согласованное состояние в дрифт.
		{name: "снято, отсутствует, признак false", desired: &absent, observed: BindingAbsent,
			effective: false, current: BindingStatusPending, want: BindingStatusSynced},
		{name: "желаемого нет — право наблюдаемое", desired: nil, observed: BindingPresent,
			effective: false, current: BindingStatusPending, want: BindingStatusObserved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveBindingStatus(tc.desired, tc.observed, tc.effective, tc.current)
			if got != tc.want {
				t.Errorf("ResolveBindingStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

// Граница между «поломка доказана» и «ещё не наблюдалось». Первая версия
// правки её не различала: свежий грант (observed unknown) считался сломанным,
// и повторная выдача плодила бы дубли операций на каждое нажатие.
func TestBindingNeedsRepair(t *testing.T) {
	present := BindingPresent
	absent := BindingAbsent

	cases := []struct {
		name      string
		desired   *BindingState
		observed  BindingState
		effective bool
		status    BindingStatus
		want      bool
	}{
		{name: "снято снаружи", desired: &present, observed: BindingAbsent,
			effective: true, status: BindingStatusDrift, want: true},
		{name: "выдано, но не действует", desired: &present, observed: BindingPresent,
			effective: false, status: BindingStatusDrift, want: true},
		{name: "выдано и работает", desired: &present, observed: BindingPresent,
			effective: true, status: BindingStatusSynced, want: false},
		{name: "свежий грант, ещё не наблюдалось", desired: &present, observed: BindingUnknown,
			effective: true, status: BindingStatusPending, want: false},
		// Провал применения — доказанная поломка: до следующего discovery
		// binding иначе неотличим от здорового и блокирует повторную выдачу,
		// которая его и чинит.
		{name: "применение упало", desired: &present, observed: BindingUnknown,
			effective: true, status: BindingStatusFailed, want: true},
		{name: "применение упало поверх выданного", desired: &present, observed: BindingPresent,
			effective: true, status: BindingStatusFailed, want: true},
		// Отзыв чинить нечего: желаемое отсутствие уже достигнуто либо
		// операция ещё идёт; провал отзыва разблокирует не выдача, а retry.
		{name: "желаемое absent", desired: &absent, observed: BindingPresent,
			effective: true, status: BindingStatusDrift, want: false},
		{name: "провал отзыва", desired: &absent, observed: BindingPresent,
			effective: true, status: BindingStatusFailed, want: false},
		{name: "unmanaged", desired: nil, observed: BindingAbsent,
			effective: true, status: BindingStatusObserved, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := Binding{
				DesiredState:      tc.desired,
				ObservedState:     tc.observed,
				ObservedEffective: tc.effective,
				Status:            tc.status,
			}
			if got := BindingNeedsRepair(b); got != tc.want {
				t.Errorf("BindingNeedsRepair = %v, want %v", got, tc.want)
			}
		})
	}
}
