package configwork

import (
	"context"
	"io"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

const MaxDocument = 8 << 20

type Options struct {
	ReadOnly bool
	StateDir string
	Open     func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	// Validate is only for isolated tests. Production uses the bound validator.
	Validate func(context.Context, config.Target, []byte, string) error
	// Host routes operations through an explicitly managed owner, including its
	// elevation policy. Nil uses ordinary local/SSH filesystem permissions.
	Host func(context.Context, config.Target, HostRequest) (HostResponse, error)
}
type Definition struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	Origin    string     `json:"origin,omitempty"`
	Type      string     `json:"type,omitempty"`
	Members   []string   `json:"members,omitempty"`
	Providers []string   `json:"providers,omitempty"`
	Provider  string     `json:"provider,omitempty"`
	Node      *yaml.Node `json:"-"`
}

func (d Definition) Raw() ([]byte, error) {
	node, err := standalone(d.Node, map[*yaml.Node]bool{})
	if err != nil {
		return nil, err
	}
	return encode(node)
}
func (d Definition) Map() map[string]any {
	var m map[string]any
	if d.Node != nil {
		_ = d.Node.Decode(&m)
	}
	return m
}

type ImportDiagnostic struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}
type Catalog struct {
	Kind       string       `json:"kind"`
	ProfileUID string       `json:"profile_uid,omitempty"`
	Files      []string     `json:"files"`
	Proxies    []Definition `json:"proxies"`
	Groups     []Definition `json:"groups"`
	Warnings   []string     `json:"warnings,omitempty"`
}
type Request struct {
	Kind         string   `json:"kind"`   // proxy or group
	Action       string   `json:"action"` // add, edit, duplicate
	Name         string   `json:"name,omitempty"`
	NewName      string   `json:"new_name,omitempty"`
	Input        []byte   `json:"-"`
	Groups       []string `json:"groups,omitempty"`
	Replace      bool     `json:"replace,omitempty"`
	OriginDigest string   `json:"origin_digest,omitempty"`
}
type Change struct {
	Path          string `json:"path"`
	BeforeSHA256  string `json:"before_sha256"`
	AfterSHA256   string `json:"after_sha256"`
	Status        string `json:"status"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	before, after []byte
}

type FieldChange struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Field     string `json:"field"`
	Operation string `json:"operation"`
	Before    any    `json:"before,omitempty"`
	After     any    `json:"after,omitempty"`
	Masked    bool   `json:"masked,omitempty"`
}
type Plan struct {
	TargetID       string        `json:"target_id"`
	SourceTargetID string        `json:"source_target_id,omitempty"`
	Owner          string        `json:"owner"`
	Action         string        `json:"action"`
	Kind           string        `json:"kind"`
	Name           string        `json:"name"`
	Digest         string        `json:"digest"`
	Changes        []Change      `json:"changes"`
	Diff           []FieldChange `json:"diff"`
	Summary        string        `json:"summary"`
	Warnings       []string      `json:"warnings,omitempty"`
	CoreVersion    string        `json:"core_version"`
	source         *source
	expected       []Definition
	expectedGroups []Definition
}
type Receipt struct {
	ID                string            `json:"id"`
	TargetID          string            `json:"target_id"`
	Binding           string            `json:"binding"`
	Owner             string            `json:"owner"`
	OwnerIdentity     string            `json:"owner_identity,omitempty"`
	Kind              string            `json:"kind"`
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	Message           string            `json:"message,omitempty"`
	Changes           []Change          `json:"changes"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	DefinitionSHA256  string            `json:"definition_sha256"`
	Definitions       map[string]string `json:"definitions,omitempty"`
	GroupSHA256       map[string]string `json:"group_sha256,omitempty"`
	SourceVerified    bool              `json:"source_verified"`
	GeneratedVerified bool              `json:"generated_verified"`
	RuntimeObserved   bool              `json:"runtime_observed"`
	Restored          bool              `json:"restored,omitempty"`
}
