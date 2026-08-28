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
)

const codeArtifactTokenRefreshBuffer = 5 * time.Minute

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

	mu         sync.Mutex
	token      string
	expiresAt  time.Time
	generation uint64
}

type codeArtifactToken struct {
	value      string
	generation uint64
}

func newCodeArtifactTokenManager(ctx context.Context, config CodeArtifactConfig) (*codeArtifactTokenManager, error) {
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.Region))
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
	return &codeArtifactTokenManager{config: config, client: client, now: now}
}

func (m *codeArtifactTokenManager) Token(ctx context.Context, rejectedGeneration uint64) (codeArtifactToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.usableToken(rejectedGeneration) {
		return codeArtifactToken{value: m.token, generation: m.generation}, nil
	}

	output, err := m.client.GetAuthorizationToken(ctx, &awscodeartifact.GetAuthorizationTokenInput{
		Domain:      aws.String(m.config.Domain),
		DomainOwner: aws.String(m.config.DomainOwner),
	})
	if err != nil {
		if rejectedGeneration == 0 && m.token != "" && m.now().Before(m.expiresAt) {
			return codeArtifactToken{value: m.token, generation: m.generation}, nil
		}
		return codeArtifactToken{}, errors.Wrap(err, "mint CodeArtifact authorization token")
	}
	if output.AuthorizationToken == nil || *output.AuthorizationToken == "" || output.Expiration == nil {
		return codeArtifactToken{}, errors.New("CodeArtifact returned an incomplete authorization token")
	}

	m.token = *output.AuthorizationToken
	m.expiresAt = *output.Expiration
	m.generation++
	return codeArtifactToken{value: m.token, generation: m.generation}, nil
}

func (m *codeArtifactTokenManager) usableToken(rejectedGeneration uint64) bool {
	if m.token == "" || !m.now().Add(codeArtifactTokenRefreshBuffer).Before(m.expiresAt) {
		return false
	}
	return rejectedGeneration == 0 || rejectedGeneration < m.generation
}
