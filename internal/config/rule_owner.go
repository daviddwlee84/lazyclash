package config

import "errors"

// RuleSourceFromConfigSource prepares an independent explicit rule binding.
// Callers must inspect it and save it only when binding rules was requested.
func RuleSourceFromConfigSource(t Target) (*RuleSource, error) {
	if t.ConfigSource == nil {
		return nil, errors.New("target has no configuration source to copy")
	}
	if err := ValidateConfigSource(t); err != nil {
		return nil, err
	}
	c := t.ConfigSource
	s := &RuleSource{Kind: c.Kind, ConfigID: c.ConfigID, Binary: c.Binary, Home: c.Home, HostPath: c.HostPath, CorePath: c.CorePath, Container: c.Container, DockerHost: c.DockerHost, ValidationDockerHost: c.ValidationDockerHost, ValidationImage: c.ValidationImage, Version: c.Version, DataDir: c.DataDir, ProfileUID: c.ProfileUID}
	if s.Kind == "native" {
		s.Kind = "mihomo"
	}
	if s.Kind == "verge" {
		s.Binary, s.Home = "", ""
	}
	candidate := t
	candidate.RuleSource = s
	if err := ValidateRuleSource(candidate); err != nil {
		return nil, err
	}
	return s, nil
}
