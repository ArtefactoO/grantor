package jobs

import (
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

func TestStatisticsSubjectOIDRequiresExactVerifiedCreationReceipt(t *testing.T) {
	acct := inventory.Account{ID: uuid.New(), ConnectionID: uuid.New(), EngineIdentity: "monitor", Status: inventory.AccountActive}
	payload := AccessPayload{StatsCreationOperationID: uuid.New(), ExpectedAccountLifecycleVersion: 4,
		StatsMembership: &postgres.StatsMembershipPins{AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "config", CredentialIncarnation: 2}}
	receipt := accountcreation.Receipt{OperationID: payload.StatsCreationOperationID, AccountID: acct.ID, ConnectionID: acct.ConnectionID,
		EngineIdentity: acct.EngineIdentity, Phase: "verified", RoleOID: 17001, LifecycleVersion: 4,
		AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "config", AdminCredentialIncarnation: 2}
	if oid, err := statsCreationSubjectOID(payload, acct, receipt); err != nil || oid != receipt.RoleOID {
		t.Fatal("exact verified creation receipt rejected")
	}
	for _, mutate := range []func(*accountcreation.Receipt){
		func(r *accountcreation.Receipt) { r.Phase = "created" },
		func(r *accountcreation.Receipt) { r.RoleOID = 0 },
		func(r *accountcreation.Receipt) { r.OperationID = uuid.New() },
		func(r *accountcreation.Receipt) { r.AccountID = uuid.New() },
		func(r *accountcreation.Receipt) { r.ConnectionID = uuid.New() },
		func(r *accountcreation.Receipt) { r.EngineIdentity = "unrelated" },
		func(r *accountcreation.Receipt) { r.TargetIdentity = "postgres:system:43" },
		func(r *accountcreation.Receipt) { r.AdminIdentity = "other_admin" },
		func(r *accountcreation.Receipt) { r.ConfigIncarnation = "other_config" },
		func(r *accountcreation.Receipt) { r.AdminCredentialIncarnation++ },
		func(r *accountcreation.Receipt) { r.LifecycleVersion++ },
	} {
		bad := receipt
		mutate(&bad)
		if _, err := statsCreationSubjectOID(payload, acct, bad); err == nil {
			t.Fatal("incomplete or foreign creation receipt supplied a subject OID")
		}
	}
}
