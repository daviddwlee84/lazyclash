package skill

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestEmbeddedSkillStructure(t *testing.T) {
	entry, err := Read("")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(entry, "---\n", 3)
	if len(parts) != 3 || parts[0] != "" {
		t.Fatal("skill entrypoint has no YAML frontmatter")
	}
	var metadata struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "lazyclash" || strings.TrimSpace(metadata.Description) == "" {
		t.Fatalf("incomplete frontmatter: %+v", metadata)
	}
	links := regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	references := map[string]bool{}
	err = fs.WalkDir(documents, "lazyclash", func(name string, item fs.DirEntry, err error) error {
		if err != nil || item.IsDir() {
			return err
		}
		data, err := documents.ReadFile(name)
		if err != nil {
			return err
		}
		for _, match := range links.FindAllStringSubmatch(string(data), -1) {
			if strings.Contains(match[1], "://") || strings.HasPrefix(match[1], "#") {
				continue
			}
			target := path.Join(path.Dir(name), strings.SplitN(match[1], "#", 2)[0])
			if _, err := documents.ReadFile(target); err != nil {
				t.Errorf("broken embedded link in %s: %s", name, match[1])
			}
			references[target] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, topic := range []string{"controllers", "runtime", "automation", "diagnosis", "workflows", "sources", "environment", "setup", "servers", "tailnet"} {
		document, err := Read(topic)
		if err != nil || strings.TrimSpace(document) == "" {
			t.Fatalf("missing topic %s: %v", topic, err)
		}
		if !references["lazyclash/references/"+topic+".md"] {
			t.Errorf("topic %s is not discoverable from the embedded guide", topic)
		}
	}
}

func TestTopicNamesCannotReadOtherPaths(t *testing.T) {
	for _, topic := range []string{"unknown", "SKILL.md", "../SKILL.md", "controllers.md", "references/controllers", "/etc/passwd", "Controllers"} {
		document, err := Read(topic)
		if !errors.Is(err, ErrUnknownTopic) || document != "" {
			t.Errorf("topic %q returned %q, %v", topic, document, err)
		}
	}
}
