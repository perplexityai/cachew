package packagepolicy //nolint:testpackage // Exercises provider and cache request amplification together.

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
)

func TestPolicyRequestWaves(t *testing.T) {
	const packages = 128
	var calls atomic.Int32
	newEvaluator := func() *cachingEvaluator {
		client, err := newSocketEvaluator(SocketConfig{
			APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
		}, false)
		assert.NoError(t, err)
		client.httpClient.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			var decoded purlRequest
			assert.NoError(t, json.NewDecoder(request.Body).Decode(&decoded))
			assert.Equal(t, 1, len(decoded.Components))
			purl := decoded.Components[0].PURL
			response, err := json.Marshal(apiArtifact{
				InputPURL: purl, Type: "npm", Name: strings.TrimSuffix(strings.TrimPrefix(purl, "pkg:npm/"), "@1.0.0"), Version: "1.0.0",
			})
			assert.NoError(t, err)
			calls.Add(1)
			time.Sleep(2 * time.Millisecond)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(response)))}, nil
		})
		return newCachingEvaluator(client, time.Minute, 15*time.Second, client.metrics)
	}
	evaluator := newEvaluator()
	for _, wave := range []struct {
		name    string
		count   int
		restart bool
		calls   int32
	}{
		{name: "cold npm install", count: packages, calls: packages},
		{name: "warm verdicts", count: 10 * packages, calls: packages},
		{name: "evaluator restart", count: packages, restart: true, calls: 2 * packages},
	} {
		t.Run(wave.name, func(t *testing.T) {
			if wave.restart {
				evaluator = newEvaluator()
			}
			started := time.Now()
			var workers sync.WaitGroup
			for worker := range 8 {
				workers.Go(func() {
					for index := worker; index < wave.count; index += 8 {
						purl := "pkg:npm/package-" + strconv.Itoa(index%packages) + "@1.0.0"
						decision, err := evaluator.Evaluate(t.Context(), purl)
						assert.NoError(t, err)
						assert.Equal(t, VerdictAllow, decision.Verdict)
					}
				})
			}
			workers.Wait()
			assert.Equal(t, wave.calls, calls.Load())
			t.Logf("%d requests, cumulative provider calls %d, elapsed %s", wave.count, calls.Load(), time.Since(started))
		})
	}
}

func TestGoArtifactWavesReuseInconclusiveResults(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			client, err := newSocketEvaluator(SocketConfig{
				APIURL: "https://socket.example.com", Organization: testOrganization, Token: testToken,
			}, false)
			assert.NoError(t, err)
			client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"alerts":[{"type":"pendingScan"}]}`))}, nil
			})
			cache := newCachingEvaluator(client, time.Minute, 15*time.Second, client.metrics)
			now := time.Now()
			cache.now = func() time.Time { return now }
			for batch := range 2 {
				for range 20 {
					for _, extension := range []string{"info", "mod", "zip"} {
						purl, ok := PackageURLForGoModule("/github.com/example/module/@v/v1.0.0." + extension)
						assert.True(t, ok)
						decision, err := cache.Evaluate(t.Context(), purl)
						assert.Equal(t, status != http.StatusOK, err != nil)
						assert.False(t, Cacheable(decision, err))
					}
				}
				assert.Equal(t, int32(batch+1), calls.Load())
				now = now.Add(15 * time.Second)
			}
		})
	}
}
