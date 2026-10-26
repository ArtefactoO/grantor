package agent

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/connector"
)

func TestCredentialsWaiterCleanupDoesNotDeleteReusedOperationID(t *testing.T) {
	waiters := newCredsWaiters()
	const id = "same-operation-two-phases"
	first := waiters.register(id)
	if !waiters.deliver(connector.CredentialsFrame{JobID: id}) {
		t.Fatal("first credentials frame was not delivered")
	}
	<-first

	second := waiters.register(id)
	// Deferred cleanup of the first phase can run after the second phase has
	// already registered the same operation-derived Job.ID.
	waiters.remove(id, first)
	if !waiters.deliver(connector.CredentialsFrame{JobID: id}) {
		t.Fatal("old waiter cleanup deleted the second phase waiter")
	}
	<-second
}
