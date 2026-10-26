// Package rolepolicies owns the generic desired/observed lifecycle of
// materialized engine roles. Engine-specific discovery, planning and exact
// verification stay in adapters; this package persists immutable intent,
// fences concurrent transitions and controls whether the resulting
// permission may be assigned.
package rolepolicies

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

var (
	ErrNotFound             = errors.New("role policies: not found")
	ErrConflict             = errors.New("role policies: state conflict")
	ErrStale                = errors.New("role policies: stale observation")
	ErrApplyUnsupported     = errors.New("role policies: apply is unsupported")
	ErrUnsafeTemplateChange = errors.New("role policies: managed or used template cannot change identity")
)

// Status is the durable policy lifecycle state shown to administrators.
type Status string

const (
	StatusObserved Status = "observed"
	StatusSynced   Status = "synced"
	StatusDrift    Status = "drift"
	StatusMissing  Status = "missing"
	StatusPending  Status = "pending"
	StatusFailed   Status = "failed"
	StatusBlocked  Status = "blocked"
)

// Action is the public lifecycle command. Adopt is deliberately verify-only;
// Create mutates only absent roles; Apply and Repair may reconcile existing ACL.
type Action string

const (
	ActionApply  Action = "apply"
	ActionAdopt  Action = "adopt"
	ActionRepair Action = "repair"
	ActionCreate Action = "create"
)

// Policy mirrors role_policies. DesiredSpec and ObservedSummary contain only
// non-secret, validated adapter data.
type Policy struct {
	ID                    uuid.UUID
	ConnectionID          uuid.UUID
	AccountID             *uuid.UUID
	TemplateKey           string
	Name                  string
	Description           string
	ExternalID            string
	DesiredSpec           adapter.RolePolicySpec
	ExpectedFingerprint   string
	ObservedFingerprint   string
	ObservedSummary       json.RawMessage
	Managed               bool
	Exact                 bool
	Dangerous             bool
	ApplySupported        bool
	BlockedReason         string
	Status                Status
	Version               int64
	TransitionOperationID *uuid.UUID
	TargetStarted         bool
	// TransitionRetryPending remains true between transient River attempts.
	// A failed operation becomes take-overable only when the worker durably
	// marks its terminal/last attempt; cancelled owners are terminal directly.
	TransitionRetryPending bool
	ObservedAt             *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// Reservation is the immutable state pinned into an operation payload after
// Reserve succeeds.
type Reservation struct {
	Policy          Policy
	ExpectedVersion int64
}

// PolicyTechnicalSpec is the public desired_spec projection. Catalog
// metadata lives next to it in Policy and is intentionally not duplicated in
// this object.
type PolicyTechnicalSpec struct {
	Engine         string                       `json:"-"`
	RoleName       string                       `json:"role_name"`
	Database       string                       `json:"database"`
	Schemas        []string                     `json:"schemas"`
	OwnerRoles     []string                     `json:"owner_roles"`
	CreatorRoles   []string                     `json:"creator_roles"`
	Profile        string                       `json:"profile"`
	RoleDatabase   string                       `json:"-"`
	InheritedRoles []adapter.MongoRoleRef       `json:"-"`
	Privileges     []adapter.MongoRolePrivilege `json:"-"`
}

func TechnicalSpec(spec adapter.RolePolicySpec) PolicyTechnicalSpec {
	out := PolicyTechnicalSpec{
		Engine: spec.Engine, RoleName: spec.RoleName, Database: spec.Database,
		Schemas:      append([]string(nil), spec.Schemas...),
		OwnerRoles:   append([]string(nil), spec.OwnerRoles...),
		CreatorRoles: append([]string(nil), spec.CreatorRoles...),
		Profile:      spec.Profile,
	}
	if spec.Engine == "mongodb" {
		out.RoleDatabase = spec.Database
		out.Database = ""
		out.InheritedRoles = append([]adapter.MongoRoleRef(nil), spec.MongoInheritedRoles...)
		out.Privileges = make([]adapter.MongoRolePrivilege, len(spec.MongoPrivileges))
		for i := range spec.MongoPrivileges {
			out.Privileges[i] = spec.MongoPrivileges[i]
			out.Privileges[i].Actions = append([]string(nil), spec.MongoPrivileges[i].Actions...)
		}
	}
	return out
}

// MarshalJSON keeps the established six-field PostgreSQL wire contract while
// exposing only MongoDB's typed role database, inheritance and privileges for
// Mongo policies. Catalog metadata and the internal Engine discriminator stay
// outside desired_spec.
func (s PolicyTechnicalSpec) MarshalJSON() ([]byte, error) {
	if s.Engine == "mongodb" {
		inherited := s.InheritedRoles
		if inherited == nil {
			inherited = []adapter.MongoRoleRef{}
		}
		privileges := s.Privileges
		if privileges == nil {
			privileges = []adapter.MongoRolePrivilege{}
		}
		return json.Marshal(struct {
			RoleName       string                       `json:"role_name"`
			RoleDatabase   string                       `json:"role_database"`
			InheritedRoles []adapter.MongoRoleRef       `json:"inherited_roles"`
			Privileges     []adapter.MongoRolePrivilege `json:"privileges"`
		}{
			RoleName: s.RoleName, RoleDatabase: s.RoleDatabase,
			InheritedRoles: inherited, Privileges: privileges,
		})
	}
	return json.Marshal(struct {
		RoleName     string   `json:"role_name"`
		Database     string   `json:"database"`
		Schemas      []string `json:"schemas"`
		OwnerRoles   []string `json:"owner_roles"`
		CreatorRoles []string `json:"creator_roles"`
		Profile      string   `json:"profile"`
	}{
		RoleName: s.RoleName, Database: s.Database, Schemas: s.Schemas,
		OwnerRoles: s.OwnerRoles, CreatorRoles: s.CreatorRoles, Profile: s.Profile,
	})
}
