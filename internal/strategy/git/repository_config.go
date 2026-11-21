package git

import (
	"path/filepath"
	"strings"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/gitclone"
)

// RepositoryConfig controls the snapshot artifacts for one exact repository.
type RepositoryConfig struct {
	Name               string `hcl:"name,label" help:"Repository key without a scheme or .git suffix, e.g. github.com/org/repo."`
	SnapshotFilter     string `hcl:"snapshot-filter,optional" help:"Partial-clone filter for the checkout snapshot, e.g. blob:none. The default is a full clone."`
	DisableLFSSnapshot bool   `hcl:"disable-lfs-snapshot,optional" help:"Skip generating and serving the separate Git LFS archive. Does not disable ordinary Git LFS requests."`
}

func (c Config) repositoryIndex() (map[string]RepositoryConfig, error) {
	index := make(map[string]RepositoryConfig, len(c.Repositories)+len(c.SnapshotFilters))
	for _, repo := range c.Repositories {
		path, err := gitclone.RepoPathFromURL("https://" + repo.Name)
		if err != nil || filepath.ToSlash(path) != repo.Name || strings.Contains(repo.Name, "*") {
			return nil, errors.Errorf("repository %q: expected an exact host/path key without a scheme or .git suffix", repo.Name)
		}
		if _, exists := index[repo.Name]; exists {
			return nil, errors.Errorf("duplicate git repository block for %q", repo.Name)
		}
		index[repo.Name] = repo
	}
	for key, filter := range c.SnapshotFilters {
		key = filepath.ToSlash(key)
		repo := index[key]
		if repo.SnapshotFilter != "" {
			return nil, errors.Errorf("repository %q: set the checkout filter in snapshot-filters or snapshot-filter, not both", key)
		}
		repo.Name = key
		repo.SnapshotFilter = filter
		index[key] = repo
	}
	return index, nil
}

func (s *Strategy) repositoryFor(upstreamURL string) RepositoryConfig {
	if len(s.repositories) != 0 {
		if path, err := gitclone.RepoPathFromURL(upstreamURL); err == nil {
			return s.repositories[filepath.ToSlash(path)]
		}
	}
	return RepositoryConfig{}
}
