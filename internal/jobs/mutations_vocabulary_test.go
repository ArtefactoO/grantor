package jobs

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// TestMutationVocabularyLock — замок против молчаливого расхождения трёх
// параллельных словарей одной мутирующей операции: operation kind (jobs,
// mutations.go), adapter capability и adapter change kind
// (adapter/types.go). Значения объявлены в разных пакетах и связаны только
// диспетчером executor.Execute и картой changeAuditActions; рассинхрон
// ломает выполнение операций молча. Инварианты:
//
//   - operation kind обязан совпадать строкой с capability (mutations.go
//     документирует «значения совпадают с capability-именами adapter»);
//     на этом строится capability-gating операции;
//   - change kind операции обязан иметь заведённые audit actions (кроме
//     credential.rotate, у которого нет DesiredChange-потока), иначе
//     executor не сможет записать исход мутации.
func TestMutationVocabularyLock(t *testing.T) {
	cases := []struct {
		name string
		kind string
		cap  adapter.Capability
		// change — пусто для операций без DesiredChange-потока
		// (credential.rotate применяет секрет напрямую).
		change adapter.ChangeKind
	}{
		{"access grant", KindAccessGrant, adapter.CapAccessGrant, adapter.ChangeGrant},
		{"access revoke", KindAccessRevoke, adapter.CapAccessRevoke, adapter.ChangeRevoke},
		{"account create", KindAccountCreate, adapter.CapAccountCreate, adapter.ChangeAccountCreate},
		{"role create", KindRoleCreate, adapter.CapRoleCreate, adapter.ChangeRoleCreate},
		{"account disable", KindAccountDisable, adapter.CapAccountDisable, adapter.ChangeAccountDisable},
		{"account enable", KindAccountEnable, adapter.CapAccountEnable, adapter.ChangeAccountEnable},
		{"account delete", KindAccountDelete, adapter.CapAccountDelete, adapter.ChangeAccountDelete},
		{"account restore", KindAccountRestore, adapter.CapAccountRestore, adapter.ChangeAccountRestore},
		{"credential rotate", KindCredentialRotate, adapter.CapCredentialRotate, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.kind != string(tc.cap) {
				t.Errorf("operation kind %q != capability %q: словари разошлись", tc.kind, string(tc.cap))
			}
			if tc.change == "" {
				return
			}
			if _, ok := changeAuditActions[tc.change]; !ok {
				t.Errorf("change kind %q has no audit actions wired", tc.change)
			}
		})
	}
}
