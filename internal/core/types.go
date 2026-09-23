package core

import (
	"context"
	"net"
	"time"
)

type Object map[string]any

type Proxy struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	All     []string      `json:"all,omitempty"`
	Now     string        `json:"now,omitempty"`
	Alive   *bool         `json:"alive,omitempty"`
	UDP     bool          `json:"udp"`
	History []DelayRecord `json:"history,omitempty"`
}

type DelayRecord struct {
	Time  string `json:"time"`
	Delay int    `json:"delay"`
}

type Options struct {
	Endpoint     string
	Secret       string
	CAFile       string
	ReadOnly     bool
	Timeout      time.Duration
	DelayURL     string
	DelayTimeout time.Duration
	DialContext  func(context.Context, string, string) (net.Conn, error)
}
