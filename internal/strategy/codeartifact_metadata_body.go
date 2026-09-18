package strategy

import (
	"bytes"
	"io"
	"net/http"
	"os"

	"github.com/alecthomas/errors"
)

type metadataBody struct {
	data []byte
	file *os.File
	size int64
}

func (b *metadataBody) close() error {
	if b.file == nil {
		return nil
	}
	err := errors.Join(b.file.Close(), os.Remove(b.file.Name())) //nolint:gosec // G703: the path comes only from os.CreateTemp, never a request.
	b.file = nil
	return errors.Wrap(err, "close metadata spool")
}

func (b *metadataBody) writeTo(w io.Writer) error {
	var reader io.Reader = bytes.NewReader(b.data)
	if b.file != nil {
		reader = io.NewSectionReader(b.file, 0, b.size)
	}
	_, err := io.Copy(w, reader)
	return errors.Wrap(err, "write package metadata")
}

type metadataCapture struct {
	headers http.Header
	status  int
	memory  bytes.Buffer
	file    *os.File
}

func (w *metadataCapture) Header() http.Header { return w.headers }
func (w *metadataCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *metadataCapture) Write(body []byte) (int, error) {
	if w.file == nil && w.memory.Len()+len(body) <= 1<<20 {
		n, err := w.memory.Write(body)
		return n, errors.Wrap(err, "capture metadata")
	}
	if w.file == nil {
		file, err := os.CreateTemp("", "cachew-metadata-*")
		if err != nil {
			return 0, errors.Wrap(err, "create metadata spool")
		}
		w.file = file
		if _, err := w.file.Write(w.memory.Bytes()); err != nil {
			return 0, errors.Wrap(err, "spill metadata")
		}
		w.memory = bytes.Buffer{}
	}
	n, err := w.file.Write(body)
	return n, errors.Wrap(err, "spool metadata")
}

func (w *metadataCapture) finish(maxBytes int) (*metadataBody, error) {
	body := &metadataBody{file: w.file}
	if w.file == nil {
		body.data = bytes.Clone(w.memory.Bytes())
		return body, nil
	}
	info, err := w.file.Stat()
	if err != nil {
		return body, errors.Wrap(err, "stat metadata spool")
	}
	body.size = info.Size()
	if body.size > int64(maxBytes) {
		return body, nil
	}
	body.data = make([]byte, int(body.size))
	_, readErr := io.ReadFull(io.NewSectionReader(w.file, 0, body.size), body.data)
	return body, errors.Join(errors.Wrap(readErr, "read metadata spool"), body.close())
}
