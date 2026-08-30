package cache

import (
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/errors"
)

// ExpirationKey carries an absolute freshness boundary through cache tiers so
// backfills cannot extend an entry beyond the lifetime selected by its writer.
const ExpirationKey = "X-Cachew-Expires-At"

func cacheEntryExpired(headers http.Header, now time.Time) bool {
	expiresAt, present, valid := cacheEntryExpiration(headers)
	if !present {
		return false
	}
	return !valid || !now.Before(expiresAt)
}

func cacheEntryTTL(headers http.Header, now time.Time) time.Duration {
	expiresAt, present, valid := cacheEntryExpiration(headers)
	if !present || !valid {
		return 0
	}
	return expiresAt.Sub(now)
}

func cacheEntryExpiration(headers http.Header) (time.Time, bool, bool) {
	value := headers.Get(ExpirationKey)
	if value == "" {
		return time.Time{}, false, false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value)
	return expiresAt, true, err == nil
}

func unexpiredCacheResult(
	body io.ReadCloser,
	headers http.Header,
	err error,
	now time.Time,
) (io.ReadCloser, http.Header, error) {
	if !cacheEntryExpired(headers, now) {
		return body, headers, err
	}
	if body == nil {
		return nil, nil, os.ErrNotExist
	}
	return nil, nil, errors.Join(os.ErrNotExist, body.Close())
}
