package strategy //nolint:testpackage // Exercise the real strategy and standard-library HTTP/2 transport.

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	goAwayIndexPath    = "/pypi/repository/simple/cachew-goaway/"
	goAwayWheelName    = "cachew_goaway-1.2.3-py3-none-any.whl"
	goAwayWheelPath    = "/pypi/repository/files/" + goAwayWheelName
	goAwayPrivateDebug = "private-origin?token=never-log-goaway-debug"
	goAwayPartialSize  = 32 << 10
)

type goAwayOriginRequest struct {
	path     string
	streamID uint32
	failed   bool
}

type goAwayOrigin struct {
	listener net.Listener
	roots    *x509.CertPool
	ca       tls.Certificate
	index    []byte
	wheel    []byte
	metadata []byte
	mu       sync.Mutex
	failures int
	requests []goAwayOriginRequest
	pending  map[string]chan struct{}
	conns    []net.Conn
	workers  sync.WaitGroup
}

func newGoAwayOrigin(t *testing.T, failures int) *goAwayOrigin {
	t.Helper()
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := certificateServer.TLS.Clone()
	tlsConfig.NextProtos = []string{http2.NextProtoTLS}
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	assert.NoError(t, err)
	metadata := []byte("Metadata-Version: 2.3\nName: cachew-goaway\nVersion: 1.2.3\nRequires-Python: >=3.12\n\n")
	var wheel bytes.Buffer
	archive := zip.NewWriter(&wheel)
	for _, file := range []struct{ name, content string }{
		{"cachew_goaway-1.2.3.dist-info/METADATA", string(metadata)},
		{"cachew_goaway-1.2.3.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: cachew-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"},
		{"cachew_goaway-1.2.3.dist-info/RECORD", ""},
	} {
		writer, createErr := archive.Create(file.name)
		assert.NoError(t, createErr)
		_, writeErr := io.WriteString(writer, file.content)
		assert.NoError(t, writeErr)
	}
	assert.NoError(t, archive.Close())
	index := fmt.Sprintf(`{"meta":{"api-version":"1.0"},"name":"cachew-goaway","padding":"%s","files":[`+
		`{"filename":%q,"url":%q,"hashes":{"sha256":"%x"},"requires-python":">=3.12","core-metadata":{"sha256":"%x"}}]}`,
		strings.Repeat("x", goAwayPartialSize), goAwayWheelName, "../../files/"+goAwayWheelName,
		sha256.Sum256(wheel.Bytes()), sha256.Sum256(metadata))
	origin := &goAwayOrigin{
		listener: listener, roots: roots, ca: tlsConfig.Certificates[0],
		index: []byte(index), wheel: wheel.Bytes(), metadata: metadata,
		failures: failures, pending: make(map[string]chan struct{}),
	}
	accepted := make(chan struct{})
	origin.workers.Go(func() {
		defer close(accepted)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			origin.mu.Lock()
			origin.conns = append(origin.conns, conn)
			origin.mu.Unlock()
			origin.workers.Go(func() {
				defer conn.Close()
				origin.serve(t, conn)
			})
		}
	})
	t.Cleanup(func() {
		assert.NoError(t, listener.Close())
		<-accepted
		origin.mu.Lock()
		for _, conn := range origin.conns {
			_ = conn.Close()
		}
		origin.mu.Unlock()
		origin.workers.Wait()
	})
	return origin
}

func (o *goAwayOrigin) serve(t *testing.T, conn net.Conn) {
	t.Helper()
	assert.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Errorf("read HTTP/2 client preface: %v", err)
		return
	}
	assert.Equal(t, http2.ClientPreface, string(preface))
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := framer.WriteSettings(); err != nil {
		t.Errorf("write HTTP/2 settings: %v", err)
		return
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					t.Errorf("acknowledge HTTP/2 settings: %v", err)
					return
				}
			}
		case *http2.PingFrame:
			if !frame.Flags.Has(http2.FlagPingAck) {
				if err := framer.WritePing(true, frame.Data); err != nil {
					t.Errorf("acknowledge HTTP/2 ping: %v", err)
					return
				}
			}
		case *http2.MetaHeadersFrame:
			path := frame.PseudoValue("path")
			o.mu.Lock()
			failed := path == goAwayIndexPath && o.failures > 0
			var written chan struct{}
			if failed {
				o.failures--
				written = make(chan struct{}, 1)
				o.pending[path] = written
			}
			o.requests = append(o.requests, goAwayOriginRequest{path, frame.StreamID, failed})
			o.mu.Unlock()
			if !o.respond(t, framer, frame.StreamID, path, written) {
				return
			}
		}
	}
}

func (o *goAwayOrigin) respond(t *testing.T, framer *http2.Framer, streamID uint32, path string, written <-chan struct{}) bool {
	t.Helper()
	body, contentType := o.index, "application/vnd.pypi.simple.v1+json"
	switch path {
	case goAwayIndexPath:
	case goAwayWheelPath:
		body, contentType = o.wheel, "application/zip"
	case goAwayWheelPath + ".metadata":
		body, contentType = o.metadata, "text/plain"
	default:
		t.Errorf("unexpected origin request: %s", path)
		return false
	}
	var headers bytes.Buffer
	encoder := hpack.NewEncoder(&headers)
	for _, field := range []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: contentType},
		{Name: "cache-control", Value: testCodeArtifactCacheControl},
	} {
		assert.NoError(t, encoder.WriteField(field))
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: headers.Bytes(), EndHeaders: true,
	}); err != nil {
		t.Errorf("write HTTP/2 response headers: %v", err)
		return false
	}
	if written != nil {
		body = body[:goAwayPartialSize]
	}
	for len(body) > 0 {
		n := min(len(body), 16<<10)
		if err := framer.WriteData(streamID, written == nil && n == len(body), body[:n]); err != nil {
			t.Errorf("write HTTP/2 response data: %v", err)
			return false
		}
		body = body[n:]
	}
	if written == nil {
		return true
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-written:
	case <-timer.C:
		t.Error("Cachew did not flush the partial body before GOAWAY")
		return false
	case <-t.Context().Done():
		return false
	}
	assert.NoError(t, framer.WriteGoAway(streamID, http2.ErrCodeNo, []byte(goAwayPrivateDebug)))
	return false
}

func (o *goAwayOrigin) observeWrite(path string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if pending := o.pending[path]; pending != nil {
		select {
		case pending <- struct{}{}:
		default:
		}
	}
}

func (o *goAwayOrigin) snapshot() []goAwayOriginRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.requests)
}

type goAwayLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *goAwayLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *goAwayLogBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data.Bytes())
}

type goAwayResponseWriter struct {
	http.ResponseWriter
	origin *goAwayOrigin
	path   string
}

func (w goAwayResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		return n, err
	}
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		return n, err
	}
	if n > 0 {
		w.origin.observeWrite(w.path)
	}
	return n, nil
}

type goAwayProxy struct {
	server   *httptest.Server
	ca       []byte
	prefix   string
	logs     *goAwayLogBuffer
	finished chan goAwayProxyRequest
}

type goAwayProxyRequest struct {
	path       string
	protoMajor int
}

func newGoAwayProxy(t *testing.T, origin *goAwayOrigin, downstream string) *goAwayProxy {
	t.Helper()
	mux, _, _, strategy, _ := newTestCachingCodeArtifact(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unexpected request to the unused HTTP origin")
	}))
	target, err := url.Parse("https://" + origin.listener.Addr().String())
	assert.NoError(t, err)
	strategy.target = target
	transport := strategy.client.Transport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{RootCAs: origin.roots, MinVersion: tls.VersionTLS12}
	t.Cleanup(transport.CloseIdleConnections)
	logs := &goAwayLogBuffer{}
	strategy.logger = slog.New(slog.NewJSONHandler(logs, nil))
	proxy := &goAwayProxy{
		prefix: strategy.prefix, ca: origin.ca.Certificate[0], logs: logs, finished: make(chan goAwayProxyRequest, 64),
	}
	proxy.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, strategy.prefix)
		defer func() { proxy.finished <- goAwayProxyRequest{path: path, protoMajor: r.ProtoMajor} }()
		mux.ServeHTTP(goAwayResponseWriter{ResponseWriter: w, origin: origin, path: path}, r)
	}))
	proxy.server.TLS = &tls.Config{
		Certificates: []tls.Certificate{goAwayProxyCertificate(t, origin.ca)}, MinVersion: tls.VersionTLS12,
	}
	proxy.server.EnableHTTP2 = downstream == "http2"
	proxy.server.StartTLS()
	t.Cleanup(proxy.server.Close)
	return proxy
}

func goAwayProxyCertificate(t *testing.T, ca tls.Certificate) tls.Certificate {
	t.Helper()
	parent, err := x509.ParseCertificate(ca.Certificate[0])
	assert.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, &key.PublicKey, ca.PrivateKey)
	assert.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der, ca.Certificate[0]}, PrivateKey: key}
}

func (p *goAwayProxy) wait(t *testing.T, path string) int {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case got := <-p.finished:
		assert.Equal(t, path, got.path)
		return got.protoMajor
	case <-timer.C:
		t.Fatal("Cachew request did not finish")
	case <-t.Context().Done():
		t.Fatal("test canceled before Cachew request finished")
	}
	return 0
}

func assertGoAwayDiagnostics(t *testing.T, proxy *goAwayProxy, origin *goAwayOrigin, count int) {
	t.Helper()
	logs := proxy.logs.snapshot()
	assert.False(t, bytes.Contains(logs, []byte(goAwayPrivateDebug)), "GOAWAY debug data must stay private")
	var failures []map[string]any
	for _, entry := range codeArtifactFailureLogs(t, logs) {
		if entry["msg"] == "CodeArtifact response stream failed" {
			failures = append(failures, entry)
		}
	}
	assert.Equal(t, count, len(failures))
	var requests []goAwayOriginRequest
	for _, request := range origin.snapshot() {
		if request.failed {
			requests = append(requests, request)
		}
	}
	assert.Equal(t, count, len(requests))
	for i, failure := range failures {
		assert.Equal[any](t, "origin", failure["source"])
		assert.Equal[any](t, "source_read", failure["stage"])
		assert.Equal[any](t, "http2_goaway", failure["error_kind"])
		assert.Equal[any](t, "NO_ERROR", failure["http2_error_code"])
		assert.Equal[any](t, float64(requests[i].streamID), failure["http2_last_stream_id"])
		assert.Equal[any](t, float64(goAwayPartialSize), failure["bytes_read"])
		assert.Equal[any](t, float64(goAwayPartialSize), failure["bytes_written"])
	}
}

func TestCodeArtifactRealGoAwayRecovery(t *testing.T) {
	for _, downstream := range []string{"http1", "http2"} {
		t.Run(downstream, func(t *testing.T) {
			origin := newGoAwayOrigin(t, 1)
			proxy := newGoAwayProxy(t, origin, downstream)
			client := proxy.server.Client()
			client.Timeout = 10 * time.Second
			for attempt := range 3 {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
					proxy.server.URL+proxy.prefix+goAwayIndexPath, nil)
				assert.NoError(t, err)
				response, err := client.Do(request)
				assert.NoError(t, err)
				body, readErr := io.ReadAll(response.Body)
				assert.NoError(t, response.Body.Close())
				proxy.wait(t, goAwayIndexPath)
				assert.Equal(t, downstream == "http2", response.ProtoMajor == 2)
				assert.Equal(t, http.StatusOK, response.StatusCode)
				if attempt == 0 {
					assert.Error(t, readErr)
					assert.True(t, len(body) > 0, "failure must occur after the client receives a partial body")
					assert.True(t, len(body) < len(origin.index))
				} else {
					assert.NoError(t, readErr)
					assert.Equal(t, origin.index, body)
				}
				assert.Equal(t, min(attempt+1, 2), len(origin.snapshot()),
					"failed fill must not be cached; complete fill must serve the warm request")
			}
			assertGoAwayDiagnostics(t, proxy, origin, 1)
		})
	}
}
