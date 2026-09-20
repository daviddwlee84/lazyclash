package selfupdate

import (
	"fmt"
	"strings"
)

// StableVersion accepts canonical release tags only. Prereleases, build
// suffixes and pseudo-versions describe development builds for this updater.
func StableVersion(version string) bool {
	_, ok := versionParts(version)
	return ok
}

// CompareVersions compares canonical stable release tags without integer
// overflow or lexical ordering mistakes (for example v0.10.0 > v0.9.0).
func CompareVersions(a, b string) (int, error) {
	ap, ok := versionParts(a)
	if !ok {
		return 0, fmt.Errorf("invalid stable version %q", a)
	}
	bp, ok := versionParts(b)
	if !ok {
		return 0, fmt.Errorf("invalid stable version %q", b)
	}
	for i := range ap {
		if len(ap[i]) < len(bp[i]) {
			return -1, nil
		}
		if len(ap[i]) > len(bp[i]) {
			return 1, nil
		}
		if cmp := strings.Compare(ap[i], bp[i]); cmp != 0 {
			return cmp, nil
		}
	}
	return 0, nil
}

func versionParts(version string) ([3]string, bool) {
	var result [3]string
	if !strings.HasPrefix(version, "v") {
		return result, false
	}
	parts := strings.Split(version[1:], ".")
	if len(parts) != len(result) {
		return result, false
	}
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return result, false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return result, false
			}
		}
		result[i] = part
	}
	return result, true
}
