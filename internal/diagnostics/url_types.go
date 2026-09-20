package diagnostics

import (
	"context"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

type URLOptions struct {
	Options
	Via           string
	ObserveOnly   bool
	ReferenceDoH  string
	Timeout       time.Duration
	HostCollector func(context.Context, string, HostRequest) (HostEvidence, error)
}

type HostRequest struct {
	URL           string `json:"url"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	ObserveOnly   bool   `json:"observe_only"`
	InventoryOnly bool   `json:"inventory_only,omitempty"`
	RequestOnly   bool   `json:"request_only,omitempty"`
	RequestKind   string `json:"request_kind,omitempty"`
}

type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}
type ProxyVariable struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}
type EnvironmentEvidence struct {
	Proxies        []ProxyVariable `json:"proxies"`
	NoProxySet     bool            `json:"no_proxy_set"`
	NoProxyMatches bool            `json:"no_proxy_matches"`
	SelectedProxy  string          `json:"selected_proxy,omitempty"`
	Interpretation string          `json:"interpretation"`
}
type DNSResult struct {
	Source    string   `json:"source"`
	Type      string   `json:"type,omitempty"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
}
type RouteEvidence struct {
	Destination string `json:"destination"`
	Interface   string `json:"interface,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Source      string `json:"source,omitempty"`
	Error       string `json:"error,omitempty"`
}
type RequestEvidence struct {
	Source                string    `json:"source"`
	Status                string    `json:"status"`
	HTTPStatus            int       `json:"http_status,omitempty"`
	Milliseconds          float64   `json:"milliseconds,omitempty"`
	DNSMilliseconds       float64   `json:"dns_milliseconds,omitempty"`
	ConnectMilliseconds   float64   `json:"connect_milliseconds,omitempty"`
	TLSMilliseconds       float64   `json:"tls_milliseconds,omitempty"`
	FirstByteMilliseconds float64   `json:"first_byte_milliseconds,omitempty"`
	LocalAddress          string    `json:"local_address,omitempty"`
	RemoteAddress         string    `json:"remote_address,omitempty"`
	Route                 string    `json:"route,omitempty"`
	StartedAt             time.Time `json:"started_at,omitempty"`
	FinishedAt            time.Time `json:"finished_at,omitempty"`
	Error                 string    `json:"error,omitempty"`
	Note                  string    `json:"note,omitempty"`
}
type HostEvidence struct {
	Protocol      int                 `json:"protocol"`
	Scope         string              `json:"scope"`
	System        string              `json:"system,omitempty"`
	Capabilities  []Capability        `json:"capabilities"`
	Environment   EnvironmentEvidence `json:"environment"`
	OSProxy       map[string]string   `json:"os_proxy,omitempty"`
	DNSConfig     []string            `json:"dns_config"`
	Interfaces    []InterfaceEvidence `json:"interfaces"`
	PolicyRouting []string            `json:"policy_routing,omitempty"`
	DNS           DNSResult           `json:"dns"`
	Routes        []RouteEvidence     `json:"routes"`
	Requests      []RequestEvidence   `json:"requests"`
	Error         string              `json:"error,omitempty"`
}
type InterfaceEvidence struct {
	Name      string   `json:"name"`
	State     string   `json:"state,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}
type OutboundEvidence struct {
	Policy       string    `json:"policy"`
	Leaf         string    `json:"leaf,omitempty"`
	Chain        []string  `json:"chain,omitempty"`
	Status       string    `json:"status"`
	Milliseconds float64   `json:"milliseconds,omitempty"`
	Error        string    `json:"error,omitempty"`
	Note         string    `json:"note"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	FinishedAt   time.Time `json:"finished_at,omitempty"`
}
type CoreEvidence struct {
	Available  bool               `json:"available"`
	Version    string             `json:"version,omitempty"`
	Mode       string             `json:"mode,omitempty"`
	TUNEnabled bool               `json:"tun_enabled"`
	TUNKnown   bool               `json:"tun_known"`
	DNS        []DNSResult        `json:"dns"`
	Outbounds  []OutboundEvidence `json:"outbounds"`
	Error      string             `json:"error,omitempty"`
}
type ConnectionEvidence struct {
	ID                 string   `json:"id"`
	Confidence         string   `json:"confidence"`
	Reason             string   `json:"reason"`
	RequestSource      string   `json:"request_source,omitempty"`
	Host               string   `json:"host,omitempty"`
	SourceAddress      string   `json:"source_address,omitempty"`
	DestinationAddress string   `json:"destination_address,omitempty"`
	InboundType        string   `json:"inbound_type,omitempty"`
	Network            string   `json:"network,omitempty"`
	Rule               string   `json:"rule,omitempty"`
	RulePayload        string   `json:"rule_payload,omitempty"`
	Chains             []string `json:"chains"`
}
type LogEvidence struct {
	Level      string `json:"level"`
	Host       string `json:"host"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}
type TopologyNode struct {
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	Confidence string `json:"confidence"`
}
type RuleRecommendation struct {
	Type       string `json:"type"`
	Domain     string `json:"domain"`
	Policy     string `json:"policy"`
	Rule       string `json:"rule"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}
type URLResult struct {
	TargetID       string               `json:"target_id"`
	URL            string               `json:"url"`
	Host           string               `json:"host"`
	SampledAt      time.Time            `json:"sampled_at"`
	ObserveOnly    bool                 `json:"observe_only"`
	Local          HostEvidence         `json:"local"`
	Remote         *HostEvidence        `json:"remote,omitempty"`
	Core           CoreEvidence         `json:"core"`
	ExplicitProxy  RequestEvidence      `json:"explicit_proxy"`
	ReferenceDNS   []DNSResult          `json:"reference_dns,omitempty"`
	Connections    []ConnectionEvidence `json:"connections"`
	Logs           []LogEvidence        `json:"logs"`
	Topology       []TopologyNode       `json:"topology"`
	Recommendation *RuleRecommendation  `json:"recommendation,omitempty"`
	Warnings       []string             `json:"warnings"`
}

// URLRunner is shared by the terminal UI and the CLI.
type URLRunner func(context.Context, config.Target, string, URLOptions) (URLResult, error)
