package strategy

import (
	"context"
	"time"

	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	awscodeartifact "github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type codeArtifactAuthorizationClient interface {
	GetAuthorizationToken(
		context.Context,
		*awscodeartifact.GetAuthorizationTokenInput,
		...func(*awscodeartifact.Options),
	) (*awscodeartifact.GetAuthorizationTokenOutput, error)
}

func newCodeArtifactClient(ctx context.Context, config CodeArtifactConfig) (*awscodeartifact.Client, error) {
	loadCtx, cancel := context.WithTimeout(ctx, config.CredentialTimeout)
	defer cancel()
	awsConfig, err := awsconfig.LoadDefaultConfig(loadCtx, awsconfig.WithRegion(config.Region))
	if err != nil {
		return nil, errors.Wrap(err, "load AWS configuration for CodeArtifact")
	}
	stsClient := sts.NewFromConfig(awsConfig)
	var provider aws.CredentialsProvider = stscreds.NewAssumeRoleProvider(stsClient, config.RoleARN)
	if config.AssetAPI {
		provider = codeArtifactCredentialDeadline(provider, config.CredentialTimeout)
	}
	awsConfig.Credentials = aws.NewCredentialsCache(provider)
	if config.AssetAPI {
		// The SDK detaches shared refreshes from caller cancellation. Bound both
		// the refresh (including retries) and each caller waiting for it.
		awsConfig.Credentials = codeArtifactCredentialDeadline(awsConfig.Credentials, config.CredentialTimeout)
	}

	return awscodeartifact.NewFromConfig(awsConfig), nil
}

func codeArtifactCredentialDeadline(provider aws.CredentialsProvider, timeout time.Duration) aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return provider.Retrieve(ctx)
	})
}

func newCodeArtifactTokenManagerWithClient(
	config CodeArtifactConfig,
	client codeArtifactAuthorizationClient,
	now func() time.Time,
) *originTokenManager {
	mint := func(ctx context.Context) (string, time.Time, error) {
		output, err := client.GetAuthorizationToken(ctx, &awscodeartifact.GetAuthorizationTokenInput{
			Domain:      aws.String(config.Domain),
			DomainOwner: aws.String(config.DomainOwner),
		})
		if err != nil {
			return "", time.Time{}, err //nolint:wrapcheck // refreshToken wraps mint errors with the origin name.
		}
		return aws.ToString(output.AuthorizationToken), aws.ToTime(output.Expiration), nil
	}
	return newOriginTokenManager("CodeArtifact", config.CredentialTimeout, mint, now)
}
