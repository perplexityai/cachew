package httputil_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/httputil"
)

func TestCacheFillCancellationGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		request, cancelRequest := context.WithCancel(t.Context())
		fill, cancelFill := httputil.CacheFillContext(request)
		defer cancelFill()
		time.Sleep(time.Minute)
		assert.NoError(t, fill.Err())
		cancelRequest()
		synctest.Wait()
		time.Sleep(29 * time.Second)
		assert.NoError(t, fill.Err())
		time.Sleep(time.Second)
		synctest.Wait()
		assert.IsError(t, fill.Err(), context.Canceled)
	})
}

func TestCacheFillExplicitCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		request, cancelRequest := context.WithCancel(t.Context())
		fill, cancelFill := httputil.CacheFillContext(request)
		cancelRequest()
		synctest.Wait()
		cancelFill()
		synctest.Wait()
		assert.IsError(t, fill.Err(), context.Canceled)
	})
}
