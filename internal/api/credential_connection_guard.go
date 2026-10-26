package api

import (
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
)

// Credential IO must observe the same configuration epoch as admin switch.
// Take connection locks before account row locks and keep them through Vault
// writes and operation reservation. Bulk callers sort the lock order.
func (s *Server) lockCredentialConnection(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	id uuid.UUID, capability adapter.Capability) (connections.Connection, bool) {
	ctx := r.Context()
	if err := locks.AcquireTx(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return connections.Connection{}, false
	}
	conn, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return connections.Connection{}, false
	}
	if conn.Status == connections.StatusCredentialUpdating {
		respondError(w, http.StatusConflict, "connection admin credential change is active")
		return connections.Connection{}, false
	}
	if conn.AuthMode == "none" {
		respondError(w, http.StatusConflict, "authentication_disabled: credential mutation is unavailable")
		return connections.Connection{}, false
	}
	if capability != "" {
		if err := requireConnectionCapability(conn, capability); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return connections.Connection{}, false
		}
	}
	return conn, true
}

func (s *Server) lockCredentialConnections(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	accounts []inventory.Account, capability adapter.Capability) bool {
	ids := make([]string, 0, len(accounts))
	seen := map[uuid.UUID]bool{}
	for _, account := range accounts {
		if !seen[account.ConnectionID] {
			seen[account.ConnectionID] = true
			ids = append(ids, account.ConnectionID.String())
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		if _, ok := s.lockCredentialConnection(w, r, tx, uuid.MustParse(id), capability); !ok {
			return false
		}
	}
	return true
}
