package config

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2/unstable"
)

func ValidDockerHost(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "unix" && u.Host == "" && u.RawQuery == "" && u.Fragment == "" && path.IsAbs(u.Path) && u.Path != "/" && u.RawPath == "" && !strings.ContainsAny(value, "\n\r\x00")
}

func ValidateClientService(s *ClientService) error {
	if s == nil {
		return nil
	}
	for _, v := range []string{s.Kind, s.DockerHost, s.Container, s.Image, s.MountsSHA256, s.ComposeFile, s.ComposeProject, s.ComposeService, s.Unit, s.Scope, s.FragmentPath, s.UnitSHA256} {
		if len(v) > 4096 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return errors.New("service binding fields contain invalid characters")
		}
	}
	switch s.Kind {
	case "docker":
		if !ValidDockerHost(s.DockerHost) || !idPattern.MatchString(s.Container) || s.Image == "" || len(s.MountsSHA256) != 64 || s.Unit != "" || s.Scope != "" || s.FragmentPath != "" || s.UnitSHA256 != "" {
			return errors.New("Docker service requires an explicit unix socket and inspected container/image/mount identity")
		}
		if s.ComposeFile != "" && (!path.IsAbs(s.ComposeFile) || !idPattern.MatchString(s.ComposeProject) || !idPattern.MatchString(s.ComposeService)) {
			return errors.New("Compose service requires absolute source, project and service")
		}
		if s.ComposeFile == "" && (s.ComposeProject != "" || s.ComposeService != "") {
			return errors.New("incomplete Compose service binding")
		}
	case "systemd":
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*\.service$`).MatchString(s.Unit) || (s.Scope != "user" && s.Scope != "system") || !path.IsAbs(s.FragmentPath) || len(s.UnitSHA256) != 64 || s.DockerHost != "" || s.Container != "" || s.Image != "" || s.MountsSHA256 != "" || s.ComposeFile != "" || s.ComposeProject != "" || s.ComposeService != "" {
			return errors.New("systemd service requires unit, user/system scope and inspected unit-file identity")
		}
	default:
		return errors.New("service kind must be docker or systemd")
	}
	return nil
}

func patchClientService(raw []byte, source *ClientService) ([]byte, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	start, end := -1, len(raw)
	for _, e := range exprs {
		if e.kind == unstable.KeyValue && e.table == "targets" && e.key == "service" {
			return nil, errors.New("inline service binding cannot be edited; use [targets.service]")
		}
		if e.kind != unstable.Table && e.kind != unstable.ArrayTable {
			continue
		}
		if start >= 0 {
			end = e.start
			break
		}
		if e.table == "targets.service" {
			start = e.start
		}
	}
	if source == nil {
		if start < 0 {
			return raw, nil
		}
		return applyEdits(raw, []edit{{start, end, nil}}), nil
	}
	b := []byte("\n[targets.service]\n")
	if start >= 0 {
		b = raw[start:end]
	}
	b, err = patchFields(b, "targets.service", []field{{"kind", source.Kind}, {"docker_host", source.DockerHost}, {"container", source.Container}, {"image", source.Image}, {"mounts_sha256", source.MountsSHA256}, {"compose_file", source.ComposeFile}, {"compose_project", source.ComposeProject}, {"compose_service", source.ComposeService}, {"unit", source.Unit}, {"scope", source.Scope}, {"fragment_path", source.FragmentPath}, {"unit_sha256", source.UnitSHA256}})
	if err != nil {
		return nil, err
	}
	if start < 0 {
		return append(append(raw, '\n'), b...), nil
	}
	return applyEdits(raw, []edit{{start, end, b}}), nil
}
