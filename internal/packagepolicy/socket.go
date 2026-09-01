package packagepolicy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"golang.org/x/sync/singleflight"
)

const (
	defaultAPIURL       = "https://api.socket.dev"
	defaultTimeout      = 30 * time.Second
	maxResponseBytes    = 4 << 20
	maxResponseLineSize = 1 << 20
)

var organizationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// SocketConfig configures Socket's organization-scoped PURL evaluator.
type SocketConfig struct {
	APIURL       string        `hcl:"api-url,optional" help:"Socket API origin." default:"https://api.socket.dev"`
	Organization string        `hcl:"organization" help:"Socket organization slug whose security policy is evaluated."`
	Token        string        `hcl:"token" help:"Socket API token with packages:list scope. Use an environment variable placeholder rather than a literal secret."`
	Timeout      time.Duration `hcl:"timeout,optional" help:"Maximum time Socket may spend resolving and scanning a package." default:"30s"`
}

type socketEvaluator struct {
	endpoint   *url.URL
	token      string
	timeoutSec int
	httpClient *http.Client
	metrics    metricRecorder
	inflight   singleflight.Group
}

var _ Evaluator = (*socketEvaluator)(nil)

// ObserveNotApplicable records a request that Cachew could not map to a PURL.
func (c *socketEvaluator) ObserveNotApplicable(ctx context.Context) {
	c.metrics.recordNotApplicable(ctx)
}

func newSocketEvaluator(config SocketConfig, allowHTTP bool) (*socketEvaluator, error) {
	if config.APIURL == "" {
		config.APIURL = defaultAPIURL
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if !organizationPattern.MatchString(config.Organization) {
		return nil, errors.New("socket policy: organization must be a non-empty slug")
	}
	if config.Token == "" {
		return nil, errors.New("socket policy: token is required")
	}
	if config.Timeout < time.Second || config.Timeout > 20*time.Minute {
		return nil, errors.New("socket policy: timeout must be between 1s and 20m")
	}

	base, err := url.Parse(config.APIURL)
	if err != nil {
		return nil, errors.Wrap(err, "socket policy: parse API URL")
	}
	validScheme := base.Scheme == "https" || (allowHTTP && base.Scheme == "http")
	if !validScheme || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("socket policy: API URL must be an HTTPS origin")
	}
	endpoint := base.JoinPath("v0", "orgs", config.Organization, "purl")

	return &socketEvaluator{
		endpoint:   endpoint,
		token:      config.Token,
		timeoutSec: int(config.Timeout / time.Second),
		httpClient: &http.Client{
			Timeout: config.Timeout + 5*time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		metrics: newMetrics("socket"),
	}, nil
}

// Evaluate returns the strictest policy result across every artifact Socket returns.
func (c *socketEvaluator) Evaluate(ctx context.Context, purl string) (Decision, error) {
	resultCh := c.inflight.DoChan(purl, func() (any, error) {
		requestCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.httpClient.Timeout)
		defer cancel()
		return c.evaluateProvider(requestCtx, purl)
	})
	select {
	case <-ctx.Done():
		return Decision{}, errors.Wrap(context.Cause(ctx), "socket policy: wait for shared evaluation")
	case result := <-resultCh:
		if result.Err != nil {
			return Decision{}, result.Err
		}
		sharedDecision, ok := result.Val.(Decision)
		if !ok {
			return Decision{}, errors.New("socket policy: invalid shared evaluation")
		}
		return sharedDecision, nil
	}
}

func (c *socketEvaluator) evaluateProvider(ctx context.Context, purl string) (decision Decision, err error) {
	started := time.Now()
	defer func() { c.metrics.record(context.WithoutCancel(ctx), decision, err, time.Since(started)) }()

	body, err := json.Marshal(purlRequest{Components: []purlComponent{{PURL: purl}}})
	if err != nil {
		return Decision{}, errors.Wrap(err, "socket policy: encode request")
	}

	endpoint := *c.endpoint
	query := endpoint.Query()
	query.Set("alerts", "true")
	query.Set("compact", "true")
	query.Set("poll", "true")
	query.Set("purlErrors", "false")
	query.Set("timeoutSec", strconv.Itoa(c.timeoutSec))
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Decision{}, errors.Wrap(err, "socket policy: build request")
	}
	req.Header.Set("Accept", "application/x-ndjson")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cachew")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Decision{}, errors.Wrap(err, "socket policy: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if _, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)); copyErr != nil {
			return Decision{}, errors.New("socket policy: read error response")
		}
		return Decision{}, errors.Errorf("socket policy: API returned %s", resp.Status)
	}

	limited := &io.LimitedReader{R: resp.Body, N: maxResponseBytes + 1}
	decision, err = evaluateStream(limited, purl)
	if err != nil {
		return Decision{}, err
	}
	if limited.N == 0 {
		return Decision{}, errors.New("socket policy: response exceeds size limit")
	}
	return decision, nil
}

type purlRequest struct {
	Components []purlComponent `json:"components"`
}

type purlComponent struct {
	PURL string `json:"purl"`
}

type apiArtifact struct {
	StreamType string  `json:"_type"`
	InputPURL  string  `json:"inputPurl"`
	Type       string  `json:"type"`
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Alerts     []alert `json:"alerts"`
}

type alert struct {
	Type   string `json:"type"`
	Action string `json:"action"`
}

type evaluationState struct {
	resolved  bool
	pending   bool
	unscanned bool
	denied    map[string]struct{}
	records   int
}

func evaluateStream(r io.Reader, requestedPURL string) (Decision, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), maxResponseLineSize)
	state := evaluationState{denied: make(map[string]struct{})}

	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		state.records++
		var decoded apiArtifact
		if err := json.Unmarshal(scanner.Bytes(), &decoded); err != nil {
			return Decision{}, errors.Wrap(err, "socket policy: decode response")
		}
		if err := state.add(decoded, requestedPURL); err != nil {
			return Decision{}, err
		}
	}
	if err := scanner.Err(); err != nil {
		return Decision{}, errors.Wrap(err, "socket policy: read response")
	}
	return state.decision()
}

func (s *evaluationState) add(artifact apiArtifact, requestedPURL string) error {
	if artifact.StreamType != "" {
		return errors.Errorf("socket policy: unexpected stream record %q", artifact.StreamType)
	}
	if artifact.InputPURL != "" && artifact.InputPURL != requestedPURL {
		return errors.New("socket policy: response PURL does not match request")
	}
	if artifact.Type != "" && artifact.Name != "" && artifact.Version != "" {
		s.resolved = true
	}
	for _, alert := range artifact.Alerts {
		switch alert.Type {
		case "pendingScan":
			s.pending = true
			continue
		case "notFound":
			s.unscanned = true
			continue
		}
		switch alert.Action {
		case "error":
			s.denied[alert.Type] = struct{}{}
		case "ignore", "monitor", "warn":
		case "":
			return errors.Errorf("socket policy: alert %q has no policy action", alert.Type)
		default:
			return errors.Errorf("socket policy: unsupported policy action %q", alert.Action)
		}
	}
	return nil
}

func (s *evaluationState) decision() (Decision, error) {
	if s.records == 0 {
		return Decision{}, errors.New("socket policy: empty response")
	}
	if len(s.denied) > 0 {
		reasons := make([]string, 0, len(s.denied))
		for reason := range s.denied {
			reasons = append(reasons, reason)
		}
		slices.Sort(reasons)
		return Decision{Verdict: VerdictDeny, Reasons: reasons}, nil
	}
	if s.pending {
		return Decision{Verdict: VerdictPending, Reasons: []string{"pendingScan"}}, nil
	}
	if s.unscanned || !s.resolved {
		return Decision{Verdict: VerdictDeny, Reasons: []string{"notFound"}}, nil
	}
	return Decision{Verdict: VerdictAllow}, nil
}
