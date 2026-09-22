// Package skill serves the operational knowledge shipped with this binary.
// Reading a document never consults the filesystem, configuration or controller.
package skill

import (
	"embed"
	"errors"
)

//go:embed lazyclash/SKILL.md lazyclash/references/*.md
var documents embed.FS

var ErrUnknownTopic = errors.New("unknown skill topic")

// Read returns the entrypoint for an empty topic, or one of the fixed references.
// Topic names are deliberately not interpreted as filesystem paths.
func Read(topic string) (string, error) {
	var path string
	switch topic {
	case "":
		path = "lazyclash/SKILL.md"
	case "controllers", "runtime", "automation", "diagnosis", "workflows", "sources", "environment", "setup", "servers", "tailnet", "analytics":
		path = "lazyclash/references/" + topic + ".md"
	default:
		return "", ErrUnknownTopic
	}
	data, err := documents.ReadFile(path)
	return string(data), err
}
