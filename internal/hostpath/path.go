// Package hostpath handles core-host paths independently of the controller OS.
// It performs lexical checks only; the host adapter must reject reparse points
// and verify ownership before accessing a file.
package hostpath

import (
	"errors"
	"path"
	"strings"
	"unicode"
)

func slash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func volume(p string) string {
	p = slash(p)
	if len(p) >= 3 && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) && p[1:3] == ":/" {
		return strings.ToUpper(p[:2])
	}
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		parts := strings.Split(strings.TrimPrefix(p, "//"), "/")
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" && parts[0] != "." && parts[0] != ".." && parts[0] != "?" && parts[1] != "." && parts[1] != ".." {
			return "//" + parts[0] + "/" + parts[1]
		}
	}
	return ""
}

func IsAbs(os, p string) bool {
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return false
	}
	if os != "windows" {
		return path.IsAbs(p)
	}
	v := volume(p)
	if v == "" {
		return false
	}
	// ADS/device paths and shell wildcard paths are not ordinary source files.
	rest := strings.TrimPrefix(slash(p), v)
	if len(v) == 2 {
		rest = slash(p)[2:]
	}
	return !strings.ContainsAny(rest, `:<>"|?*`) && !strings.ContainsAny(v, `<>"|?*`)
}

func Clean(os, p string) string {
	if os != "windows" {
		return path.Clean(p)
	}
	p = slash(p)
	v := volume(p)
	if v == "" {
		return path.Clean(p)
	}
	return v + path.Clean("/"+p[len(v):])
}

func Join(os string, parts ...string) string {
	if os != "windows" {
		return path.Join(parts...)
	}
	normalized := make([]string, len(parts))
	for i, p := range parts {
		normalized[i] = slash(p)
	}
	if len(parts) == 0 {
		return ""
	}
	return Clean(os, strings.Join(normalized, "/"))
}

func Dir(os, p string) string {
	if os != "windows" {
		return path.Dir(p)
	}
	p = Clean(os, p)
	v := volume(p)
	if v == "" {
		return path.Dir(p)
	}
	return v + path.Dir("/"+p[len(v):])
}

func Base(os, p string) string {
	if os == "windows" {
		p = slash(p)
	}
	return path.Base(p)
}

func Rel(os, base, p string) (string, error) {
	if !IsAbs(os, base) || !IsAbs(os, p) {
		return "", errors.New("host paths must be absolute")
	}
	base, p = Clean(os, base), Clean(os, p)
	equal := func(a, b string) bool { return a == b }
	if os == "windows" {
		equal = strings.EqualFold
		bv, pv := volume(base), volume(p)
		if !equal(bv, pv) {
			return "", errors.New("host paths use different volumes")
		}
		base, p = base[len(bv):], p[len(pv):]
	}
	a, b := strings.Split(strings.Trim(base, "/"), "/"), strings.Split(strings.Trim(p, "/"), "/")
	if len(a) == 1 && a[0] == "" {
		a = nil
	}
	if len(b) == 1 && b[0] == "" {
		b = nil
	}
	i := 0
	for i < len(a) && i < len(b) && equal(a[i], b[i]) {
		i++
	}
	result := make([]string, 0, len(a)+len(b)-2*i)
	for j := i; j < len(a); j++ {
		result = append(result, "..")
	}
	result = append(result, b[i:]...)
	if len(result) == 0 {
		return ".", nil
	}
	return strings.Join(result, "/"), nil
}

func Within(os, root, p string) bool {
	rel, err := Rel(os, root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func IsRoot(os, p string) bool {
	if !IsAbs(os, p) {
		return false
	}
	p = Clean(os, p)
	if os == "windows" {
		return p == volume(p)+"/"
	}
	return p == "/"
}
