package api

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/readscope"
)

func (s *Server) readScope(ctx context.Context, sess auth.Session) (*readscope.Scope, error) {
	if !s.scopeApplies(sess) {
		return nil, nil
	}
	environments, allowAll, err := s.allowedEnvironments(ctx, sess)
	if err != nil {
		return nil, err
	}
	return &readscope.Scope{Environments: environments, AllowAll: allowAll,
		ActorType: sess.ActorType(), ActorID: sess.ActorID()}, nil
}

func (s *Server) checkOperationReadScope(ctx context.Context, sess auth.Session, id uuid.UUID) error {
	return s.checkOperationReadScopeWith(ctx, s.pool, sess, id)
}

func (s *Server) checkOperationReadScopeWith(ctx context.Context, q operations.Querier, sess auth.Session, id uuid.UUID) error {
	scope, err := s.readScope(ctx, sess)
	if err != nil || scope == nil {
		return err
	}
	args := []any{id}
	predicate := scope.Operation("$1::uuid", &args)
	var allowed bool
	if err := q.QueryRow(ctx, "select "+predicate, args...).Scan(&allowed); err != nil {
		return fmt.Errorf("api: check operation scope: %w", err)
	}
	if !allowed {
		return errScopeForbidden
	}
	return nil
}

func (s *Server) visibleConnectionIDs(ctx context.Context, sess auth.Session) (map[uuid.UUID]bool, error) {
	if !s.scopeApplies(sess) {
		return nil, nil
	}
	connections, err := s.connections.List(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	connections, err = s.filterConnectionsByScope(ctx, sess, connections)
	if err != nil {
		return nil, err
	}
	ids := make(map[uuid.UUID]bool, len(connections))
	for i := range connections {
		ids[connections[i].ID] = true
	}
	return ids, nil
}
