package configwork

import (
	"github.com/daviddwlee84/lazyclash/internal/config"
	"go.yaml.in/yaml/v3"
)

// ConfigObject is a named definition, one rule occurrence, or a read-only
// top-level section. Value is display-only; Node must stay in private memory.
type ConfigObject struct {
	ID              string     `json:"id"`
	Kind            string     `json:"kind"`
	Name            string     `json:"name"`
	Section         string     `json:"section"`
	Origin          string     `json:"origin,omitempty"`
	Index           int        `json:"index"`
	Selectable      bool       `json:"selectable"`
	ReadOnlyReason  string     `json:"read_only_reason,omitempty"`
	ResourceSHA256  string     `json:"resource_sha256,omitempty"`
	ResourceStatus  string     `json:"resource_status,omitempty"`
	ResourceMessage string     `json:"resource_message,omitempty"`
	Value           any        `json:"value"`
	Node            *yaml.Node `json:"-"`
	resource        *HostFile
}

type ConfigSnapshot struct {
	TargetID string         `json:"target_id"`
	Owner    string         `json:"owner"`
	Shape    string         `json:"shape"`
	Digest   string         `json:"digest"`
	Complete bool           `json:"complete"`
	Files    []string       `json:"files"`
	Objects  []ConfigObject `json:"objects"`
	Warnings []string       `json:"warnings,omitempty"`
	Target   config.Target  `json:"-"`
	Root     *yaml.Node     `json:"-"`
	target   config.Target
	source   *source
}

type StructuralFieldChange struct {
	Path          string `json:"path"`
	Operation     string `json:"operation"`
	BeforePresent bool   `json:"before_present"`
	AfterPresent  bool   `json:"after_present"`
	BeforeType    string `json:"before_type,omitempty"`
	AfterType     string `json:"after_type,omitempty"`
	Before        any    `json:"before"`
	After         any    `json:"after"`
	Masked        bool   `json:"masked,omitempty"`
}

// ObjectDiff describes making Destination match Source. Before is destination,
// After is source. A destination-only row is inspection-only, never deletion.
type ObjectDiff struct {
	ID                  string                  `json:"id"`
	Kind                string                  `json:"kind"`
	Name                string                  `json:"name"`
	Section             string                  `json:"section"`
	Status              string                  `json:"status"`
	SourceID            string                  `json:"source_id,omitempty"`
	DestinationID       string                  `json:"destination_id,omitempty"`
	Before              *ConfigObject           `json:"before,omitempty"`
	After               *ConfigObject           `json:"after,omitempty"`
	Fields              []StructuralFieldChange `json:"fields"`
	Unified             string                  `json:"unified"`
	Selectable          bool                    `json:"selectable"`
	ReplacementRequired bool                    `json:"replacement_required"`
	OrderChanged        bool                    `json:"order_changed,omitempty"`
}

type ConfigDiff struct {
	SourceTargetID      string       `json:"source_target_id"`
	DestinationTargetID string       `json:"destination_target_id"`
	SourceShape         string       `json:"source_shape"`
	DestinationShape    string       `json:"destination_shape"`
	Complete            bool         `json:"complete"`
	Equal               bool         `json:"equal_compared_configuration"`
	Objects             []ObjectDiff `json:"objects"`
	Warnings            []string     `json:"warnings,omitempty"`
}

type ObjectSelection struct {
	ID      string `json:"id"`
	Replace bool   `json:"replace,omitempty"`
}

type DependencyDecision struct {
	ID     string `json:"id"`
	Action string `json:"action"` // reuse or replace
}

type GroupAttachment struct {
	ProxyID string   `json:"proxy_id"`
	Groups  []string `json:"groups"`
}

type StructuralSelection struct {
	Objects                 []ObjectSelection    `json:"objects"`
	Dependencies            []DependencyDecision `json:"dependencies,omitempty"`
	RulePlacement           string               `json:"rule_placement,omitempty"` // anchored or prepend
	AllowVergeRulesOverride bool                 `json:"allow_verge_rules_override,omitempty"`
	AttachGroups            []GroupAttachment    `json:"attach_groups,omitempty"`
}

type StructuralBlocker struct {
	Code         string `json:"code"`
	ObjectID     string `json:"object_id,omitempty"`
	DependencyID string `json:"dependency_id,omitempty"`
	Message      string `json:"message"`
}

type StructuralComposition struct {
	Selected            []string            `json:"selected"`
	AutoSelected        []string            `json:"auto_selected"`
	Reused              []string            `json:"reused"`
	RequiredBy          map[string][]string `json:"required_by"`
	Blockers            []StructuralBlocker `json:"blockers"`
	Warnings            []string            `json:"warnings,omitempty"`
	Diff                ConfigDiff          `json:"diff"`
	Root                *yaml.Node          `json:"-"`
	SourceSnapshot      *ConfigSnapshot     `json:"-"`
	DestinationSnapshot *ConfigSnapshot     `json:"-"`
	Definitions         []Definition        `json:"-"`
	Rules               []string            `json:"-"`
	// Same-package owner execution can retain existing guarded-source machinery.
	source        *source
	baseline      *source
	expected      []Definition
	expectedRules []string
}
