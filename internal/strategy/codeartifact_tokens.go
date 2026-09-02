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
	codeArtifactTokenRefreshBuffer         = 5 * time.Minute
	codeArtifactTokenRefreshFailureBackoff = time.Minute
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
	generation uint64
	retryAfter time.Time
}

type codeArtifactToken struct {
	value      string
	generation uint64
	event      codeArtifactAuthEvent
}

func newCodeArtifactTokenManager(ctx context.Context, config CodeArtifactConfig) (*codeArtifactTokenManager, error) {
	config = codeArtifactConfigWithDefaults(config)
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
		config:  codeArtifactConfigWithDefaults(config),
		client:  client,
		now:     now,
		refresh: semaphore.NewWeighted(1),
	}
}

func (m *codeArtifactTokenManager) Token(ctx context.Context, rejectedGeneration uint64) (codeArtifactToken, error) {
	if token, ok := m.reusableToken(rejectedGeneration); ok {
		return token, nil
	}

	refreshCtx, cancel := context.WithTimeout(ctx, m.config.CredentialTimeout)
	defer cancel()
	if err := m.refresh.Acquire(refreshCtx, 1); err != nil {
		return codeArtifactToken{}, errors.Wrap(err, "wait for CodeArtifact authorization refresh")
	}
	defer m.refresh.Release(1)

	if token, ok := m.reusableToken(rejectedGeneration); ok {
		return token, nil
	}

	output, err := m.client.GetAuthorizationToken(refreshCtx, &awscodeartifact.GetAuthorizationTokenInput{
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
	m.generation++
	m.retryAfter = time.Time{}
	event := codeArtifactAuthRefresh
	if rejectedGeneration != 0 {
		event = codeArtifactAuthForcedRefresh
	}
	return codeArtifactToken{value: m.token, generation: m.generation, event: event}, nil
}

func (m *codeArtifactTokenManager) reusableToken(rejectedGeneration uint64) (codeArtifactToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.usableTokenLocked(rejectedGeneration) {
		return codeArtifactToken{}, false
	}
	return codeArtifactToken{value: m.token, generation: m.generation, event: codeArtifactAuthReuse}, true
}

func (m *codeArtifactTokenManager) usableTokenLocked(rejectedGeneration uint64) bool {
	now := m.now()
	if m.token == "" || !now.Before(m.expiresAt) {
		return false
	}
	if rejectedGeneration == 0 && now.Before(m.retryAfter) {
		return true
	}
	if !now.Add(codeArtifactTokenRefreshBuffer).Before(m.expiresAt) {
		return false
	}
	return rejectedGeneration == 0 || rejectedGeneration < m.generation
}
