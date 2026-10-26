// Package connectionregistration stores durable onboarding intent. It never
// stores credential values or derivatives; a versioned approved source is the
// immutable credential identity used for replay and crash recovery.
package connectionregistration

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound = errors.New("connection registration: not found")
	ErrConflict = errors.New("connection registration: intent conflict")
)

type Owner struct {
	Type string
	ID   uuid.UUID
}

func (o Owner) Valid() bool { return (o.Type == "service" || o.Type == "user") && o.ID != uuid.Nil }

type Source struct {
	ID             uuid.UUID
	Name           string
	Owner          Owner
	Environment    string
	TargetSpec     json.RawMessage
	Version        int
	Status         string
	CleanupPending bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	RevokedAt      *time.Time
}

type Registration struct {
	ID                      uuid.UUID
	Owner                   Owner
	RegistrationKey         string
	Environment             string
	Spec                    json.RawMessage
	CredentialSourceID      uuid.UUID
	CredentialSourceVersion int
	ConnectionID            uuid.UUID
	OperationID             uuid.UUID
	Phase                   string
	CanonicalVersion        int
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// SourcePath accepts only a server-issued UUID, never a caller-selected path,
// mount, username or identity-provider subject.
func SourcePath(id uuid.UUID) string { return "onboarding/sources/" + id.String() }
