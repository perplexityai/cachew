package strategy

import (
	"context"
	"sync"
	"time"

	"github.com/alecthomas/errors"
	"golang.org/x/sync/semaphore"
)

const (
	originTokenProactiveRefreshWindow = time.Hour
	originTokenRefreshFailureBackoff  = time.Minute
)

type originAuthEvent string

const (
	originAuthReuse         originAuthEvent = "reuse"
	originAuthRefresh       originAuthEvent = "refresh"
	originAuthForcedRefresh originAuthEvent = "forced_refresh"
	originAuthFailure       originAuthEvent = "failure"
)

type originTokenSource interface {
	// Token returns a usable token. rejectedGeneration is zero for a normal
	// lookup. When non-zero, it identifies the token generation an origin
	// rejected so a concurrent refresh can be reused instead of repeated.
	Token(context.Context, uint64) (originToken, error)
}

type originTokenState uint8

const (
	originTokenNeedsRefresh originTokenState = iota
	originTokenReusable
	originTokenRefreshDue
)

// originTokenManager caches a short-lived origin authorization token and
// refreshes it before expiry. CodeArtifact and ECR both mint theirs through an
// assumed role; mint is the only origin-specific part.
type originTokenManager struct {
	origin            string
	credentialTimeout time.Duration
	mint              originTokenMinter
	now               func() time.Time

	mu         sync.RWMutex
	refresh    *semaphore.Weighted
	token      string
	expiresAt  time.Time
	refreshAt  time.Time
	generation uint64
	retryAfter time.Time
}

type originToken struct {
	value      string
	generation uint64
	event      originAuthEvent
}

// originTokenMinter returns a new token and its expiry. An empty token or a
// zero expiry is an incomplete response, which is never retried with the
// previous token.
type originTokenMinter func(context.Context) (string, time.Time, error)

func newOriginTokenManager(
	origin string,
	credentialTimeout time.Duration,
	mint originTokenMinter,
	now func() time.Time,
) *originTokenManager {
	return &originTokenManager{
		origin:            origin,
		credentialTimeout: credentialTimeout,
		mint:              mint,
		now:               now,
		refresh:           semaphore.NewWeighted(1),
	}
}

func (m *originTokenManager) Token(ctx context.Context, rejectedGeneration uint64) (originToken, error) {
	token, state := m.currentToken(rejectedGeneration)
	if state == originTokenReusable {
		return token, nil
	}

	refreshParent := ctx
	if state == originTokenRefreshDue {
		// The current request can disappear without invalidating an early refresh
		// that benefits every later request using this token manager.
		refreshParent = context.WithoutCancel(ctx)
	}
	refreshCtx, cancel := context.WithTimeout(refreshParent, m.credentialTimeout)
	defer cancel()
	initialGeneration := token.generation
	if state == originTokenRefreshDue {
		// A valid token can keep serving while one caller refreshes it early. Only
		// rejected or expired generations need to queue behind an active refresh.
		if !m.refresh.TryAcquire(1) {
			return token, nil
		}
	} else {
		if err := m.refresh.Acquire(refreshCtx, 1); err != nil {
			return originToken{}, errors.Wrapf(err, "wait for %s authorization refresh", m.origin)
		}
	}
	defer m.refresh.Release(1)

	token, state = m.currentToken(rejectedGeneration)
	if state == originTokenReusable ||
		(state == originTokenRefreshDue && token.generation != initialGeneration) {
		return token, nil
	}

	return m.refreshToken(refreshCtx, rejectedGeneration)
}

func (m *originTokenManager) refreshToken(
	ctx context.Context,
	rejectedGeneration uint64,
) (originToken, error) {
	value, expiresAt, err := m.mint(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		now := m.now()
		if rejectedGeneration == 0 && m.token != "" && now.Before(m.expiresAt) {
			m.retryAfter = now.Add(originTokenRefreshFailureBackoff)
			return originToken{value: m.token, generation: m.generation, event: originAuthFailure}, nil
		}
		return originToken{}, errors.Wrapf(err, "mint %s authorization token", m.origin)
	}
	if value == "" || expiresAt.IsZero() {
		return originToken{}, errors.Errorf("%s returned an incomplete authorization token", m.origin)
	}

	m.token = value
	m.expiresAt = expiresAt
	m.refreshAt = originTokenRefreshTime(m.now(), m.expiresAt)
	m.generation++
	m.retryAfter = time.Time{}
	event := originAuthRefresh
	if rejectedGeneration != 0 {
		event = originAuthForcedRefresh
	}
	return originToken{value: m.token, generation: m.generation, event: event}, nil
}

func (m *originTokenManager) currentToken(
	rejectedGeneration uint64,
) (originToken, originTokenState) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now()
	token := originToken{value: m.token, generation: m.generation, event: originAuthReuse}
	if m.token == "" || !now.Before(m.expiresAt) {
		return token, originTokenNeedsRefresh
	}
	if rejectedGeneration != 0 {
		if rejectedGeneration < m.generation {
			return token, originTokenReusable
		}
		return token, originTokenNeedsRefresh
	}
	if now.Before(m.retryAfter) || now.Before(m.refreshAt) {
		return token, originTokenReusable
	}
	return token, originTokenRefreshDue
}

func originTokenRefreshTime(now, expiresAt time.Time) time.Time {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return expiresAt
	}
	window := originTokenProactiveRefreshWindow
	if halfLifetime := remaining / 2; halfLifetime < window {
		window = halfLifetime
	}
	return expiresAt.Add(-window)
}
