package gomod

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os/exec"
	"strings"

	"github.com/alecthomas/errors"
	"github.com/goproxy/goproxy"
	"golang.org/x/mod/module"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/gitclone"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/packagepolicy"
	"github.com/block/cachew/internal/strategy"
)

const disableModuleFetchHeader = "Disable-Module-Fetch"

func Register(r *strategy.Registry, cloneManager gitclone.ManagerProvider) {
	strategy.Register(r, "gomod", "Caches Go module proxy requests.", func(ctx context.Context, config Config, cache cache.Cache, mux strategy.Mux) (*Strategy, error) {
		return New(ctx, config, cache, mux, cloneManager)
	})
}

type Config struct {
	Proxy         string                `hcl:"proxy,optional" help:"Upstream Go module proxy URL (defaults to proxy.golang.org)" default:"https://proxy.golang.org"`
	PrivatePaths  []string              `hcl:"private-paths,optional" help:"Module path patterns for private repositories"`
	PackagePolicy *packagepolicy.Config `hcl:"package-policy,block,optional" help:"Optional package security policy enforced before cold public module downloads."`
}

type Strategy struct {
	config        Config
	cache         cache.Cache
	logger        *slog.Logger
	proxy         *url.URL
	goproxy       *goproxy.Goproxy
	cacher        *goproxyCacher
	packagePolicy packagepolicy.Evaluator
	proxyHandler  http.Handler
	cloneManager  *gitclone.Manager
}

var _ strategy.Strategy = (*Strategy)(nil)

func New(ctx context.Context, config Config, cache cache.Cache, mux strategy.Mux, cloneManagerProvider gitclone.ManagerProvider) (*Strategy, error) {
	if len(config.PrivatePaths) > 0 {
		if _, err := exec.LookPath("git"); err != nil {
			return nil, errors.New("git is required for private module support but not found in PATH")
		}
	}

	parsedURL, err := url.Parse(config.Proxy)
	if err != nil {
		return nil, errors.Errorf("invalid proxy URL: %w", err)
	}

	cloneManager, err := cloneManagerProvider()
	if err != nil {
		return nil, errors.Errorf("failed to create clone manager: %w", err)
	}

	s := &Strategy{
		config:       config,
		cache:        cache,
		logger:       logging.FromContext(ctx),
		proxy:        parsedURL,
		cloneManager: cloneManager,
	}
	if config.PackagePolicy != nil {
		s.packagePolicy, err = packagepolicy.New(*config.PackagePolicy)
		if err != nil {
			return nil, errors.Wrap(err, "create package policy")
		}
	}

	publicFetcher := &goproxy.GoFetcher{
		Env: []string{
			"GOPROXY=" + config.Proxy,
			"GOSUMDB=off", // Disable checksum database validation in fetcher, to prevent unneccessary double validation
		},
	}

	var fetcher goproxy.Fetcher = publicFetcher

	if len(config.PrivatePaths) > 0 {
		s.cloneManager = cloneManager
		privateFetcher := newPrivateFetcher(s.logger, cloneManager)
		fetcher = NewCompositeFetcher(publicFetcher, privateFetcher, config.PrivatePaths)

		s.logger.InfoContext(ctx, "Configured private module support", "private-paths", config.PrivatePaths)
	}

	s.cacher = &goproxyCacher{cache: cache}
	s.goproxy = &goproxy.Goproxy{
		Logger:  s.logger,
		Fetcher: fetcher,
		Cacher:  s.cacher,
		ProxiedSumDBs: []string{
			"sum.golang.org https://sum.golang.org",
		},
	}

	s.logger.InfoContext(ctx, "Initialized Go module proxy strategy", "proxy", s.proxy)

	s.proxyHandler = http.StripPrefix("/gomod", s.goproxy)
	mux.Handle("GET /gomod/{path...}", http.HandlerFunc(s.serveHTTP))

	return s, nil
}

func (s *Strategy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/gomod/")
	purl, ok := packagepolicy.PackageURLForGoModule("/" + path)
	if s.packagePolicy == nil {
		s.proxyHandler.ServeHTTP(w, r)
		return
	}
	if !ok || s.privateModulePath(path) {
		s.packagePolicy.ObserveNotApplicable(r.Context())
		s.proxyHandler.ServeHTTP(w, r)
		return
	}
	if s.cached(path, r) {
		r.Header.Set(disableModuleFetchHeader, "true")
		s.proxyHandler.ServeHTTP(w, r)
		return
	}
	decision, err := s.packagePolicy.Evaluate(r.Context(), purl)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "Package policy evaluation failed", "error", err)
	}
	if !packagepolicy.AllowRequest(w, decision, err) {
		return
	}
	s.proxyHandler.ServeHTTP(w, r)
}

func (s *Strategy) cached(path string, r *http.Request) bool {
	if s.cacher == nil || r.URL.RawQuery != "" || r.Header.Get("Range") != "" {
		return false
	}
	return s.cacher.Exists(r.Context(), path)
}

func (s *Strategy) privateModulePath(requestPath string) bool {
	if len(s.config.PrivatePaths) == 0 {
		return false
	}
	escapedPath, _, ok := strings.Cut(requestPath, "/@v/")
	if !ok {
		return false
	}
	modulePath, err := module.UnescapePath(escapedPath)
	if err != nil {
		return false
	}
	return isPrivateModule(s.config.PrivatePaths, modulePath)
}

func (s *Strategy) String() string {
	return "gomod:" + s.proxy.Host
}
