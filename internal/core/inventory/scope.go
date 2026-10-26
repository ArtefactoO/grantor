package inventory

// Нормализация области действия (scope) binding — единая форма для API,
// access-манифеста и любого будущего кода, который сопоставляет desired- и
// observed-состояние прав.
//
// # Зачем
//
// У части движков область действия — свойство самого permission-определения,
// а не отдельного решения оператора: kafka `topic-produce:<topic>` неотделим
// от топика, mongodb `role:<db>.<name>` — от базы, rabbitmq
// `vhost-access:<vhost>` — от vhost. Discovery фиксирует observed-binding с
// этим scope, поэтому desired-binding, созданный без scope, не совпадает с
// ним: unique-ключ bindings — (account_id, permission_definition_id,
// scope_resource_id) с `nulls not distinct`, то есть NULL и конкретный
// resource дают ДВЕ разные строки. Результат — вечный ложный drift плюс
// фантомный «внешний грант» на каждый выданный доступ.
//
// Поэтому scope binding выводится, а не берётся из запроса как есть:
// незаданная область действия наследуется от permission-определения.
// Движки, у которых permission cluster-wide (postgres, mysql, redis, роли
// clickhouse), не затрагиваются: у них ScopeResourceID пуст и вывод даёт
// прежний NULL.

import "github.com/google/uuid"

// EffectiveBindingScope возвращает scope_resource_id, который обязан нести
// binding на permission perm при явно запрошенной области requested.
// requested == nil означает «оператор область не задавал» — тогда берётся
// собственная область permission-определения (nil у cluster-wide прав).
//
// Функция тотальна и идемпотентна: повторное применение к собственному
// результату его не меняет, поэтому её безопасно вызывать в любой точке пути
// выдачи.
func EffectiveBindingScope(perm Permission, requested *uuid.UUID) *uuid.UUID {
	if requested != nil {
		return requested
	}
	return perm.ScopeResourceID
}

// ScopeConflicts сообщает, что явно запрошенная область requested
// противоречит собственной области permission-определения. Такой грант
// заведомо расходится с observed-состоянием: адаптеры выводят целевой объект
// из самого permission (topic, база, vhost), поэтому binding на чужом
// resource никогда не совпадёт с тем, что вернёт discovery.
//
// requested == nil конфликтом не является: это и есть случай наследования.
// Permission без собственной области тоже не конфликтует — там scope задаёт
// вызывающий.
func ScopeConflicts(perm Permission, requested *uuid.UUID) bool {
	if requested == nil || perm.ScopeResourceID == nil {
		return false
	}
	return *requested != *perm.ScopeResourceID
}

// SameScope сравнивает две области действия по значению: обе пустые или обе
// указывают на один resource. Сравнение указателей напрямую здесь неверно —
// scope приходит из разных источников (строка bindings, определение
// permission, тело запроса).
func SameScope(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// BindingHasPermissionScope сообщает, что binding лежит в собственной области
// своего permission-определения, то есть выражает «право P у аккаунта A» без
// дополнительного сужения оператором. Такие bindings и создаёт выдача через
// API, UI и access-манифест после нормализации области.
func BindingHasPermissionScope(b Binding, perm Permission) bool {
	return SameScope(b.ScopeResourceID, perm.ScopeResourceID)
}
