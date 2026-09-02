package git

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/errors"
)

type rawFileProvider struct {
	file *os.File
}

func (r rawFileProvider) Read([]byte) (int, error) {
	return 0, errors.New("buffered fallback used")
}

func (r rawFileProvider) RawFile() *os.File { return r.file }

func TestServeReaderFastUsesExposedFile(t *testing.T) {
	contents := []byte("snapshot")
	path := filepath.Join(t.TempDir(), "snapshot.bundle")
	assert.NoError(t, os.WriteFile(path, contents, 0600))
	file, err := os.Open(path)
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, file.Close()) })

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/snapshot.bundle", nil)
	written, err := serveReaderFast(response, request, rawFileProvider{file: file})
	assert.NoError(t, err)
	assert.Equal(t, int64(len(contents)), written)
	assert.Equal(t, contents, response.Body.Bytes())
}
