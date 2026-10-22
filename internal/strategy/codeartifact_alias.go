package strategy

import (
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/alecthomas/errors"
)

// CodeArtifactAliasConfig decouples client download paths from repository layout.
type CodeArtifactAliasConfig struct {
	Pattern string `hcl:"pattern,label" help:"Absolute route with single-segment {name} wildcards."`
	Path    string `hcl:"path" help:"Absolute origin path; {name} substitutes a route wildcard."`
}

var aliasName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
var aliasSegment = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)
var aliasSubstitution = regexp.MustCompile(`\{([^}]+)\}`)

func validateCodeArtifactAlias(alias CodeArtifactAliasConfig) ([]string, error) {
	if !strings.HasPrefix(alias.Pattern, "/") || strings.HasSuffix(alias.Pattern, "/") || path.Clean(alias.Pattern) != alias.Pattern {
		return nil, errors.New("codeartifact: alias must be a canonical absolute file route")
	}
	names := []string{}
	used := map[string]bool{}
	for segment := range strings.SplitSeq(strings.TrimPrefix(alias.Pattern, "/"), "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
			if !aliasName.MatchString(name) || used[name] {
				return nil, errors.New("codeartifact: invalid or repeated alias wildcard")
			}
			used[name] = true
			names = append(names, name)
		} else if !aliasSegment.MatchString(segment) {
			return nil, errors.New("codeartifact: invalid alias path segment")
		}
	}
	target := alias.Path
	for _, match := range aliasSubstitution.FindAllStringSubmatch(target, -1) {
		if !used[match[1]] {
			return nil, errors.New("codeartifact: alias refers to an unknown wildcard")
		}
		target = strings.ReplaceAll(target, match[0], "value")
	}
	if !strings.HasPrefix(target, "/") || path.Clean(target) != target || strings.HasSuffix(target, "/") {
		return nil, errors.New("codeartifact: alias target must be a canonical absolute file path")
	}
	for segment := range strings.SplitSeq(strings.TrimPrefix(target, "/"), "/") {
		if !aliasSegment.MatchString(segment) {
			return nil, errors.New("codeartifact: invalid alias target segment")
		}
	}
	return names, nil
}

func (c *CodeArtifact) registerAliases(config CodeArtifactConfig, mux Mux) (err error) {
	defer func() {
		if conflict := recover(); conflict != nil {
			err = errors.Errorf("codeartifact: conflicting alias routes: %v", conflict)
		}
	}()
	for _, alias := range config.Aliases {
		names, err := validateCodeArtifactAlias(alias)
		if err != nil {
			return err
		}
		if _, err := codeArtifactMavenAsset(aliasSubstitution.ReplaceAllString(alias.Path, "value")); err != nil {
			return errors.Wrap(err, "codeartifact: invalid asset-api alias target")
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path {
				http.NotFound(w, r)
				return
			}
			target := alias.Path
			for _, name := range names {
				value := r.PathValue(name)
				if !aliasSegment.MatchString(value) || value == "." || value == ".." {
					http.NotFound(w, r)
					return
				}
				target = strings.ReplaceAll(target, "{"+name+"}", value)
			}
			request := r.Clone(r.Context())
			request.URL.Path = c.prefix + target
			request.URL.RawPath = ""
			c.ServeHTTP(w, request)
		})
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			mux.Handle(method+" "+alias.Pattern, handler)
		}
	}
	return nil
}
