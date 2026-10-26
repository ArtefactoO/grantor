package api

import (
	"context"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
)

type personalKeyAuthenticator struct {
	q      apikey.Querier
	store  *apikey.Store
	issuer string
}

func NewPersonalKeyAuth(q apikey.Querier, store *apikey.Store, currentIssuer string) auth.TokenAuthenticator {
	return personalKeyAuthenticator{q: q, store: store, issuer: currentIssuer}
}

func (a personalKeyAuthenticator) AuthenticateToken(ctx context.Context, token string) (auth.Session, bool) {
	if a.issuer == "" {
		return auth.Session{}, false
	}
	identity, err := a.store.Authenticate(ctx, a.q, token)
	if err != nil || identity.User.Issuer != a.issuer {
		return auth.Session{}, false
	}
	return auth.Session{
		Issuer: identity.User.Issuer, Subject: identity.User.Subject, Username: identity.User.Username,
		Email: identity.User.Email, Role: identity.Role, OwnerRole: identity.User.Role, ExpiresAt: identity.ExpiresAt,
		APIKeyID: identity.KeyID.String(), APIUserID: identity.User.ID.String(), Environments: identity.Environments,
	}, true
}

type tokenAuthenticators []auth.TokenAuthenticator

func ChainTokenAuthenticators(authenticators ...auth.TokenAuthenticator) auth.TokenAuthenticator {
	return tokenAuthenticators(authenticators)
}

func (a tokenAuthenticators) AuthenticateToken(ctx context.Context, token string) (auth.Session, bool) {
	for _, candidate := range a {
		if candidate == nil {
			continue
		}
		if session, ok := candidate.AuthenticateToken(ctx, token); ok {
			return session, true
		}
	}
	return auth.Session{}, false
}
