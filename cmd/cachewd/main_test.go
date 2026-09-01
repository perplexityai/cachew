package main

import (
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"
)

func TestLoadGlobalConfigRequestAdmission(t *testing.T) {
	ast, err := hcl.Parse(strings.NewReader(`
request-admission {
  limit = 512
  reserved = 8
}
log {
  level = "info"
}
`))
	assert.NoError(t, err)
	config, _, err := loadGlobalConfig(ast)
	assert.NoError(t, err)
	assert.Equal(t, 512, config.RequestAdmission.Limit)
	assert.Equal(t, 8, config.RequestAdmission.Reserved)
}
