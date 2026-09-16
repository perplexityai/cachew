package gomod

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"github.com/goproxy/goproxy"
	"golang.org/x/mod/module"
)

// CompositeFetcher routes module requests to either public or private fetchers based on module path patterns.
type CompositeFetcher struct {
	publicFetcher  goproxy.Fetcher
	privateFetcher goproxy.Fetcher
	patterns       []string
}

func NewCompositeFetcher(
	publicFetcher goproxy.Fetcher,
	privateFetcher goproxy.Fetcher,
	patterns []string,
) *CompositeFetcher {
	return &CompositeFetcher{
		publicFetcher:  publicFetcher,
		privateFetcher: privateFetcher,
		patterns:       patterns,
	}
}

func (c *CompositeFetcher) IsPrivate(modulePath string) bool {
	return isPrivateModule(c.patterns, modulePath)
}

func isPrivateModule(patterns []string, modulePath string) bool {
	return module.MatchPrefixPatterns(strings.Join(patterns, ","), modulePath)
}

func (c *CompositeFetcher) Query(ctx context.Context, path, query string) (version string, t time.Time, err error) {
	if c.IsPrivate(path) {
		v, tm, err := c.privateFetcher.Query(ctx, path, query)
		return v, tm, errors.Wrap(err, "private fetcher query")
	}
	v, tm, err := c.publicFetcher.Query(ctx, path, query)
	return v, tm, errors.Wrap(err, "public fetcher query")
}

func (c *CompositeFetcher) List(ctx context.Context, path string) (versions []string, err error) {
	if c.IsPrivate(path) {
		v, err := c.privateFetcher.List(ctx, path)
		return v, errors.Wrap(err, "private fetcher list")
	}
	v, err := c.publicFetcher.List(ctx, path)
	return v, errors.Wrap(err, "public fetcher list")
}

func (c *CompositeFetcher) Download(ctx context.Context, path, version string) (info, mod, zip io.ReadSeekCloser, err error) {
	if c.IsPrivate(path) {
		i, m, z, err := c.privateFetcher.Download(ctx, path, version)
		return i, m, z, errors.Wrap(err, "private fetcher download")
	}
	i, m, z, err := c.publicFetcher.Download(ctx, path, version)
	return i, m, z, errors.Wrap(err, "public fetcher download")
}
