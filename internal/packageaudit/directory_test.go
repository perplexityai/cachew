package packageaudit //nolint:testpackage // Exercises owner validation without requiring root or changing file ownership.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/alecthomas/assert/v2"
)

type auditDirectoryInfo struct {
	os.FileInfo
	mode  os.FileMode
	owner uint32
}

func (i auditDirectoryInfo) Mode() os.FileMode { return i.mode }
func (i auditDirectoryInfo) IsDir() bool       { return i.mode.IsDir() }
func (i auditDirectoryInfo) Sys() any          { return &syscall.Stat_t{Uid: i.owner} }

func TestAuditDirectoryOwnersAndModes(t *testing.T) {
	for _, test := range []struct {
		name  string
		owner uint32
		mode  os.FileMode
		leaf  bool
		valid bool
	}{
		{name: "private leaf", owner: 1234, mode: os.ModeDir | 0700, leaf: true, valid: true},
		{name: "foreign leaf", owner: 5678, mode: os.ModeDir | 0700, leaf: true},
		{name: "root leaf", owner: 0, mode: os.ModeDir | 0700, leaf: true},
		{name: "readable leaf", owner: 1234, mode: os.ModeDir | 0750, leaf: true},
		{name: "root ancestor", owner: 0, mode: os.ModeDir | 0755, valid: true},
		{name: "owned ancestor", owner: 1234, mode: os.ModeDir | 0755, valid: true},
		{name: "foreign ancestor", owner: 5678, mode: os.ModeDir | 0755},
		{name: "writable ancestor", owner: 0, mode: os.ModeDir | 0777},
		{name: "group writable ancestor", owner: 1234, mode: os.ModeDir | 0770},
		{name: "root temporary parent", owner: 0, mode: os.ModeDir | os.ModeSticky | 0777, valid: true},
		{name: "owned temporary parent", owner: 1234, mode: os.ModeDir | os.ModeSticky | 0777, valid: true},
		{name: "foreign sticky parent", owner: 5678, mode: os.ModeDir | os.ModeSticky | 0777},
		{name: "file", owner: 1234, mode: 0700, leaf: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkAuditDirectory(auditDirectoryInfo{mode: test.mode, owner: test.owner}, 1234, test.leaf)
			assert.Equal(t, test.valid, err == nil)
		})
	}
}

func TestAuditDirectoryWalkAndAliases(t *testing.T) {
	parent := t.TempDir()
	assert.NoError(t, os.Mkdir(filepath.Join(parent, "private"), 0755))
	assert.NoError(t, os.Mkdir(filepath.Join(parent, "private", "tmp"), 0755))
	assert.NoError(t, os.Symlink("private/tmp", filepath.Join(parent, "alias")))
	for _, directory := range []string{
		filepath.Join(parent, "nested", "audit"),
		filepath.Join(parent, "alias", "audit"),
	} {
		root, err := openAuditRoot(directory)
		assert.NoError(t, err)
		info, err := root.Stat(".")
		assert.NoError(t, err)
		assert.NoError(t, checkAuditDirectory(info, os.Geteuid(), true))
		assert.NoError(t, root.Close())
	}
	assert.NoError(t, os.Symlink("nested/audit", filepath.Join(parent, "leaf-alias")))
	assert.NoError(t, os.Symlink(parent, filepath.Join(parent, "absolute-alias")))
	assert.NoError(t, os.Symlink("..", filepath.Join(parent, "parent-alias")))
	assert.NoError(t, os.Symlink("private/../nested", filepath.Join(parent, "traversing-alias")))
	for _, directory := range []string{
		"", "relative", "/", filepath.Join(parent, "leaf-alias"),
		filepath.Join(parent, "absolute-alias", "audit"), filepath.Join(parent, "parent-alias", "audit"),
		filepath.Join(parent, "traversing-alias", "audit"),
	} {
		_, err := openAuditRoot(directory)
		assert.Error(t, err)
	}
}

func TestAuditDirectoryDoesNotCreateUnderUntrustedParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "writable")
	assert.NoError(t, os.Mkdir(parent, 0700))
	assert.NoError(t, os.Chmod(parent, 0777))
	leaf := filepath.Join(parent, "must-not-exist")
	_, err := openAuditRoot(leaf)
	assert.Error(t, err)
	_, err = os.Stat(leaf)
	assert.True(t, os.IsNotExist(err))
	assert.NoError(t, os.Mkdir(filepath.Join(parent, "owned"), 0700))
	alias := filepath.Join(filepath.Dir(parent), "alias")
	assert.NoError(t, os.Symlink("writable/owned", alias))
	_, err = openAuditRoot(filepath.Join(alias, "audit"))
	assert.Error(t, err)
	assert.NoError(t, os.Chmod(parent, os.ModeSticky|0777))
	root, err := openAuditRoot(leaf)
	assert.NoError(t, err)
	assert.NoError(t, root.Close())
}

func TestAuditDirectoryRejectsChangedComponent(t *testing.T) {
	parent, err := os.OpenRoot(t.TempDir())
	assert.NoError(t, err)
	defer parent.Close()
	assert.NoError(t, parent.Mkdir("audit", 0700))
	before, err := parent.Lstat("audit")
	assert.NoError(t, err)
	assert.NoError(t, parent.Rename("audit", "old"))
	assert.NoError(t, parent.Mkdir("audit", 0700))
	_, err = openAuditChild(parent, "audit", before, os.Geteuid(), true)
	assert.Error(t, err)
}
