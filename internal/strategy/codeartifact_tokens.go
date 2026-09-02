package strategy

import (
	"context"
	"sync"
	"time"

	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/semaphore"
)

const (
	codeArtifactTokenProactiveRefreshWindow = time.Hour
	codeArtifactTokenRefreshFailureBackoff  = time.Minute
)

type codeArtifactTokenState uint8

const (
	codeArtifactTokenNeedsRefresh codeArtifactTokenState = iota
	codeArtifactTokenReusable
	codeArtifactTokenRefreshDue
)

type codeArtifactAuthorizationClient interface {
	GetAuthorizationToken(
		context.Context,
		*awscodeartifact.GetAuthorizationTokenInput,
		...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error)
}

type codeArtifactTokenManager struct {
	config CodeArtifactConfig
	client codeArtifactAuthorizationClient
	now    func() time.Time

	mu         sync.RWMutex
	refresh    *semaphore.Weighted
	token      string
	expiresAt  time.Time
	refreshAt  time.Time
	generation uint64
	retryAfter time.Time
}

type codeArtifactToken struct {
	value      string
	generation uint64
	event      codeArtifactAuthEvent
}

func newCodeArtifactTokenManager(ctx context.Context, config CodeArtifactConfig) (*codeArtifactTokenManager, error) {
	loadCtx, cancel := context.WithTimeout(ctx, config.CredentialTimeout)
	defer cancel()
	awsConfig, err := awsconfig.LoadDefaultConfig(loadCtx, awsconfig.WithRegion(config.Region))
	if err != nil {
		return nil, errors.Wrap(err, "load AWS configuration for CodeArtifact")
	}
	stsClient := sts.NewFromConfig(awsConfig)
	awsConfig.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, config.RoleARN))

	return newCodeArtifactTokenManagerWithClient(config, awscodeartifact.NewFromConfig(awsConfig), time.Now), nil
}

func newCodeArtifactTokenManagerWithClient(
	config CodeArtifactConfig,
	client codeArtifactAuthorizationClient,
	now func() time.Time,
) *codeArtifactTokenManager {
	return &codeArtifactTokenManager{
		config:  config,
		client:  client,
		now:     now,
		refresh: semaphore.NewWeighted(1),
	}
}

func (m *codeArtifactTokenManager) Token(ctx context.Context, rejectedGeneration uint64) (codeArtifactToken, error) {
	token, state := m.currentToken(rejectedGeneration)
	if state == codeArtifactTokenReusable {
		return token, nil
	}

	refreshParent := ctx
	if state == codeArtifactTokenRefreshDue {
		// The current request can disappear without invalidating an early refresh
		// that benefits every later request using this token manager.
		refreshParent = context.WithoutCancel(ctx)
	}
	refreshCtx, cancel := context.WithTimeout(refreshParent, m.config.CredentialTimeout)
	defer cancel()
	initialGeneration := token.generation
	if state == codeArtifactTokenRefreshDue {
		// A valid token can keep serving while one caller refreshes it early. Only
		// rejected or expired generations need to queue behind an active refresh.
		if !m.refresh.TryAcquire(1) {
			return token, nil
		}
	} else {
		if err := m.refresh.Acquire(refreshCtx, 1); err != nil {
			return codeArtifactToken{}, errors.Wrap(err, "wait for CodeArtifact authorization refresh")
		}
	}
	defer m.refresh.Release(1)

	token, state = m.currentToken(rejectedGeneration)
	if state == codeArtifactTokenReusable ||
		(state == codeArtifactTokenRefreshDue && token.generation != initialGeneration) {
		return token, nil
	}

	return m.refreshToken(refreshCtx, rejectedGeneration)
}

func (m *codeArtifactTokenManager) refreshToken(
	ctx context.Context,
	rejectedGeneration uint64,
) (codeArtifactToken, error) {
	output, err := m.client.GetAuthorizationToken(ctx, &awscodeartifact.GetAuthorizationTokenInput{
		Domain:      aws.String(m.config.Domain),
		DomainOwner: aws.String(m.config.DomainOwner),
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		now := m.now()
		if rejectedGeneration == 0 && m.token != "" && now.Before(m.expiresAt) {
			m.retryAfter = now.Add(codeArtifactTokenRefreshFailureBackoff)
			return codeArtifactToken{value: m.token, generation: m.generation, event: codeArtifactAuthFailure}, nil
		}
		return codeArtifactToken{}, errors.Wrap(err, "mint CodeArtifact authorization token")
	}
	if output.AuthorizationToken == nil || *output.AuthorizationToken == "" || output.Expiration == nil {
		return codeArtifactToken{}, errors.New("CodeArtifact returned an incomplete authorization token")
	}

	m.token = *output.AuthorizationToken
	m.expiresAt = *output.Expiration
	m.refreshAt = codeArtifactTokenRefreshTime(m.now(), m.expiresAt)
	m.generation++
	m.retryAfter = time.Time{}
	event := codeArtifactAuthRefresh
	if rejectedGeneration != 0 {
		event = codeArtifactAuthForcedRefresh
	}
	return codeArtifactToken{value: m.token, generation: m.generation, event: event}, nil
}

func (m *codeArtifactTokenManager) currentToken(
	rejectedGeneration uint64,
) (codeArtifactToken, codeArtifactTokenState) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now()
	token := codeArtifactToken{value: m.token, generation: m.generation, event: codeArtifactAuthReuse}
	if m.token == "" || !now.Before(m.expiresAt) {
		return token, codeArtifactTokenNeedsRefresh
	}
	if rejectedGeneration != 0 {
		if rejectedGeneration < m.generation {
			return token, codeArtifactTokenReusable
		}
		return token, codeArtifactTokenNeedsRefresh
	}
	if now.Before(m.retryAfter) || now.Before(m.refreshAt) {
		return token, codeArtifactTokenReusable
	}
	return token, codeArtifactTokenRefreshDue
}

func codeArtifactTokenRefreshTime(now, expiresAt time.Time) time.Time {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return expiresAt
	}
	window := codeArtifactTokenProactiveRefreshWindow
	if halfLifetime := remaining / 2; halfLifetime < window {
		window = halfLifetime
	}
	return expiresAt.Add(-window)
}
