package selfupdate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type symlinkSnapshot struct {
	path, target string
	info         os.FileInfo
}

type installationSnapshot struct {
	executable, resolved string
	links                []symlinkSnapshot
	file                 os.FileInfo
	digest               [sha256.Size]byte
}

func snapshotInstallation(installation Installation) (installationSnapshot, error) {
	resolved, links, err := resolveLinks(installation.Executable)
	if err != nil {
		return installationSnapshot{}, err
	}
	if resolved != installation.ResolvedPath {
		return installationSnapshot{}, errors.New("executable symlink target changed; retry upgrade")
	}
	info, digest, err := fingerprint(resolved)
	if err != nil {
		return installationSnapshot{}, err
	}
	if installation.fileInfo != nil && !sameFileState(installation.fileInfo, info) {
		return installationSnapshot{}, errors.New("executable changed after its installation metadata was inspected; retry upgrade")
	}
	return installationSnapshot{executable: installation.Executable, resolved: resolved, links: links, file: info, digest: digest}, nil
}

func (s installationSnapshot) validate() error {
	resolved, links, err := resolveLinks(s.executable)
	if err != nil || resolved != s.resolved || len(links) != len(s.links) {
		return errors.New("executable path or symlink changed during upgrade; the replacement was canceled")
	}
	for i, link := range links {
		old := s.links[i]
		if link.path != old.path || link.target != old.target || !sameFileState(old.info, link.info) {
			return errors.New("executable symlink changed during upgrade; the replacement was canceled")
		}
	}
	info, digest, err := fingerprint(s.resolved)
	if err != nil || !sameFileState(s.file, info) || s.digest != digest {
		return errors.New("executable changed during upgrade; the replacement was canceled")
	}
	return nil
}

func sameFileState(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func fingerprint(path string) (os.FileInfo, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	before, err := os.Lstat(path)
	if err != nil {
		return nil, digest, err
	}
	if !before.Mode().IsRegular() {
		return nil, digest, errors.New("update destination must be a regular executable file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, digest, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameFileState(before, opened) {
		return nil, digest, errors.New("executable changed while reading it")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, digest, err
	}
	after, err := file.Stat()
	if err != nil || !sameFileState(opened, after) {
		return nil, digest, errors.New("executable changed while reading it")
	}
	copy(digest[:], hash.Sum(nil))
	return opened, digest, nil
}

// resolveLinks records every traversed link, including links in parent
// directories and links reached through another link's relative target.
func resolveLinks(path string) (string, []symlinkSnapshot, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	var links []symlinkSnapshot
	for followed := 0; followed < 255; followed++ {
		volume := filepath.VolumeName(path)
		root := volume + string(filepath.Separator)
		parts := strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator))
		current := root
		found := false
		for i, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil {
				return "", nil, err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			target, err := os.Readlink(current)
			if err != nil {
				return "", nil, err
			}
			links = append(links, symlinkSnapshot{current, target, info})
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			path = filepath.Join(append([]string{target}, parts[i+1:]...)...)
			found = true
			break
		}
		if !found {
			return filepath.Clean(path), links, nil
		}
	}
	return "", nil, fmt.Errorf("too many symbolic links in executable path")
}
