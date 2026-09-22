package packageaudit

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/alecthomas/errors"
)

// Root confines paths but does not validate ownership. Pin and check every ancestor before creating anything beneath
// it, including when a trusted system alias expands to several directories under a sticky temporary parent.
func openAuditRoot(directory string) (*os.Root, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return nil, errors.New("package audit directory must be a nonempty absolute path")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, errors.Errorf("open package audit filesystem root: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = root.Close()
		}
	}()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(directory), "/"), "/")
	uid := os.Geteuid()
	rootInfo, err := root.Stat(".")
	if err != nil {
		return nil, errors.Errorf("inspect package audit filesystem root: %w", err)
	}
	if err := checkAuditDirectory(rootInfo, uid, false); err != nil {
		return nil, err
	}
	links := 0
	for len(parts) != 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			return nil, errors.New("package audit directory must name a dedicated directory")
		}
		info, err := root.Lstat(part)
		if os.IsNotExist(err) {
			if err := root.Mkdir(part, 0700); err != nil && !os.IsExist(err) {
				return nil, errors.Errorf("create private package audit directory: %w", err)
			}
			info, err = root.Lstat(part)
		}
		if err != nil {
			return nil, errors.Errorf("inspect package audit path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if len(parts) == 0 || links > 40 || !auditTrustedOwner(info, uid) {
				return nil, errors.New("package audit path contains an unsupported or untrusted symlink")
			}
			target, err := root.Readlink(part)
			if err != nil {
				return nil, errors.Errorf("read package audit ancestor alias: %w", err)
			}
			if !filepath.IsLocal(target) || filepath.Clean(target) == "." || slices.Contains(strings.Split(target, "/"), "..") {
				return nil, errors.New("package audit ancestor aliases must point to relative descendants")
			}
			parts = append(strings.Split(filepath.Clean(target), "/"), parts...)
			continue
		}
		next, err := openAuditChild(root, part, info, uid, len(parts) == 0)
		if err != nil {
			return nil, err
		}
		_ = root.Close()
		root = next
	}
	success = true
	return root, nil
}

func openAuditChild(parent *os.Root, name string, before os.FileInfo, uid int, leaf bool) (*os.Root, error) {
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, errors.Errorf("open package audit path component: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, errors.Errorf("inspect opened package audit directory: %w", err)
	}
	if !os.SameFile(before, info) {
		_ = root.Close()
		return nil, errors.New("package audit directory changed while opening")
	}
	if err := checkAuditDirectory(info, uid, leaf); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func checkAuditDirectory(info os.FileInfo, uid int, leaf bool) error {
	if !info.IsDir() || !auditTrustedOwner(info, uid) {
		return errors.New("package audit path directories must be owned by root or the effective user")
	}
	if leaf {
		owner := info.Sys().(*syscall.Stat_t).Uid
		if int64(owner) != int64(uid) || info.Mode().Perm() != 0700 {
			return errors.New("package audit directory must be owned by the effective user with mode 0700")
		}
	} else if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("package audit ancestors must not be group- or world-writable without the sticky bit")
	}
	return nil
}

func auditTrustedOwner(info os.FileInfo, uid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || int64(stat.Uid) == int64(uid))
}
