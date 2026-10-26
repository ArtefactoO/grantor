package jobs

import (
	"sync"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
	"github.com/ArtefactoO/grantor/internal/core/connections"
)

// Регистрация глобальна и падает на дубле, поэтому идёт ровно один раз:
// приведение identity к engine-форме проверяется на настоящем адаптере.
var registerMySQLOnceJobs sync.Once

// Отметка учётки, под которой grantor управляет подключением. Без неё
// оператор видит обычную unmanaged-строку, жмёт «Принять под управление» и
// получает 409 постфактум; с ней UI прячет действие заранее.
func TestMarkConnectionAdminAccount(t *testing.T) {
	adminFlag := func(a adapter.ObservedAccount) bool {
		return adapter.AttrBool(a.Attributes, adapter.AttrConnectionAdmin)
	}

	t.Run("отмечает учётку по сырому username", func(t *testing.T) {
		snap := &adapter.Snapshot{Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: "grantor"},
			{Kind: "login", EngineIdentity: "app_user"},
		}}
		markConnectionAdminAccount(
			connections.Connection{Engine: "postgres"},
			adapter.Connection{AdminCredential: adapter.Credential{Username: "grantor"}},
			snap,
		)
		if !adminFlag(snap.Accounts[0]) {
			t.Error("admin account is not marked")
		}
		if adminFlag(snap.Accounts[1]) {
			t.Error("unrelated account must stay unmarked")
		}
	})

	// mysql публикует identity как user@host: без приведения к engine-форме
	// username `root` не совпал бы с `root@%`.
	t.Run("отмечает учётку по engine-форме identity", func(t *testing.T) {
		registerMySQLOnceJobs.Do(func() {
			adapter.Register(mysql.Engine, func() adapter.Adapter { return mysql.New() })
		})
		snap := &adapter.Snapshot{Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: "root@%"},
		}}
		markConnectionAdminAccount(
			connections.Connection{Engine: mysql.Engine},
			adapter.Connection{AdminCredential: adapter.Credential{Username: "root"}},
			snap,
		)
		if !adminFlag(snap.Accounts[0]) {
			t.Error("admin account in engine identity form is not marked")
		}
	})

	// Подключение без Vault-пути к admin credential (external_identity):
	// имени учётки grantor не знает, помечать нечего — но и падать нельзя.
	t.Run("пустой username ничего не помечает", func(t *testing.T) {
		snap := &adapter.Snapshot{Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: "grantor"},
		}}
		markConnectionAdminAccount(
			connections.Connection{Engine: "postgres"},
			adapter.Connection{},
			snap,
		)
		if adminFlag(snap.Accounts[0]) {
			t.Error("account must stay unmarked without an admin username")
		}
	})

	t.Run("nil-снапшот не паникует", func(t *testing.T) {
		markConnectionAdminAccount(
			connections.Connection{Engine: "postgres"},
			adapter.Connection{AdminCredential: adapter.Credential{Username: "grantor"}},
			nil,
		)
	})
}
