package connectionfavorites

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOwnerRequiresExactlyOneStableIdentity(t *testing.T) {
	id, zero, epoch := uuid.New(), uuid.Nil, time.Now()
	zeroTime := time.Time{}
	for _, owner := range []Owner{
		{}, {UserID: &id}, {UserIdentityBoundAt: &epoch}, {UserID: &id, UserIdentityBoundAt: &zeroTime},
		{UserID: &zero, UserIdentityBoundAt: &epoch}, {ServicePrincipalID: &zero},
		{ServicePrincipalID: &id, UserID: &id, UserIdentityBoundAt: &epoch}, {ServicePrincipalID: &id, UserIdentityBoundAt: &epoch},
	} {
		if _, err := NewStore().List(t.Context(), nil, owner, nil, true); !errors.Is(err, ErrInvalidOwner) {
			t.Fatalf("invalid owner reached database: %+v, %v", owner, err)
		}
		if err := NewStore().Set(t.Context(), nil, owner, uuid.New(), true); !errors.Is(err, ErrInvalidOwner) {
			t.Fatalf("invalid owner mutated database: %+v, %v", owner, err)
		}
	}
	for _, owner := range []Owner{{UserID: &id, UserIdentityBoundAt: &epoch}, {ServicePrincipalID: &id}} {
		if !owner.valid() {
			t.Fatalf("valid owner rejected: %+v", owner)
		}
	}
}
