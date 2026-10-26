// Package readscope builds the same authorization predicate for paginated
// reads, their counts and individual receipts. Values are always bound SQL
// parameters; callers supply only static, internal column expressions.
package readscope

import "fmt"

type Scope struct {
	Environments []string
	AllowAll     bool
	ActorType    string
	ActorID      string
}

// Connection excludes deleted or unknown connections as well as foreign
// environments: an absent reference cannot prove authorization.
func (s *Scope) Connection(connectionID string, args *[]any) string {
	if s.AllowAll {
		return "exists (select 1 from connections scope_connection where scope_connection.id = " + connectionID + ")"
	}
	*args = append(*args, s.Environments)
	return fmt.Sprintf("exists (select 1 from connections scope_connection where scope_connection.id = %s and scope_connection.environment = any($%d::text[]))", connectionID, len(*args))
}

func (s *Scope) actor(actorType, actorID string, args *[]any) string {
	*args = append(*args, s.ActorType, s.ActorID)
	return fmt.Sprintf("(%s = $%d and %s = $%d)", actorType, len(*args)-1, actorID, len(*args))
}

// Operation checks the entire descendant tree before returning the root's
// payload or aggregate outcome. UNION also terminates malformed cyclic trees.
// Unattached global operations are visible only to their own actor.
func (s *Scope) Operation(operationID string, args *[]any) string {
	connection := s.Connection("scope_node.connection_id", args)
	account := s.Connection("scope_account.connection_id", args)
	resource := s.Connection("scope_resource.connection_id", args)
	binding := s.Connection("scope_binding_account.connection_id", args)
	actor := s.actor("scope_root.actor_type", "scope_root.actor_id", args)
	return fmt.Sprintf(`exists (
		with recursive scope_tree as (
			select id, connection_id, account_id, resource_id, binding_id from operations where id = %s
			union
			select child.id, child.connection_id, child.account_id, child.resource_id, child.binding_id
			from operations child join scope_tree parent on child.parent_id = parent.id
		)
		select 1 from operations scope_root where scope_root.id = %s
		and not exists (
			select 1 from scope_tree scope_node where
			(scope_node.connection_id is not null and not (%s))
			or (scope_node.account_id is not null and not exists
				(select 1 from accounts scope_account where scope_account.id = scope_node.account_id and %s))
			or (scope_node.resource_id is not null and not exists
				(select 1 from resources scope_resource where scope_resource.id = scope_node.resource_id and %s))
			or (scope_node.binding_id is not null and not exists
				(select 1 from bindings scope_binding join accounts scope_binding_account on scope_binding_account.id = scope_binding.account_id
				where scope_binding.id = scope_node.binding_id and %s))
		)
		and (exists (select 1 from scope_tree where connection_id is not null or account_id is not null or resource_id is not null or binding_id is not null)
			or %s)
	)`, operationID, operationID, connection, account, resource, binding, actor)
}

// Audit checks both an event's own references and its correlated operation.
// A connection-free standalone event carries no verifiable environment and
// therefore remains private to the actor that produced it.
func (s *Scope) Audit(alias string, args *[]any) string {
	connection := s.Connection(alias+".connection_id", args)
	account := s.Connection("scope_audit_account.connection_id", args)
	resource := s.Connection("scope_audit_resource.connection_id", args)
	operation := s.Operation(alias+".operation_id", args)
	actor := s.actor(alias+".actor_type", alias+".actor_id", args)
	return fmt.Sprintf(`((%s.connection_id is null or %s)
		and (%s.account_id is null or exists (select 1 from accounts scope_audit_account where scope_audit_account.id = %s.account_id and %s))
		and (%s.resource_id is null or exists (select 1 from resources scope_audit_resource where scope_audit_resource.id = %s.resource_id and %s))
		and ((%s.operation_id is not null and %s)
			or (%s.operation_id is null and (%s.connection_id is not null or %s.account_id is not null or %s.resource_id is not null or %s))))`,
		alias, connection, alias, alias, account, alias, alias, resource,
		alias, operation, alias, alias, alias, alias, actor)
}
