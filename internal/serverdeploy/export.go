package serverdeploy

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/skip2/go-qrcode"
	"go.yaml.in/yaml/v3"
)

func ClientNode(ctx context.Context, id string, o Options) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j, err := loadJournal(o, id)
	if err != nil {
		return nil, err
	}
	if !j.Approved || j.Phase == "removed" {
		return nil, errors.New("only a deployed service can export client credentials")
	}
	return yaml.Marshal(clientMap(j))
}

func Export(ctx context.Context, id, format string, o Options) ([]byte, error) {
	node, err := ClientNode(ctx, id, o)
	if err != nil {
		return nil, err
	}
	j, err := loadJournal(o, id)
	if err != nil {
		return nil, err
	}
	if format == "yaml" || format == "mihomo" {
		return node, nil
	}
	definitions, _, err := configwork.ParseImport(node)
	if err != nil || len(definitions) != 1 {
		return nil, errors.New("generated client node cannot be encoded")
	}
	uri, err := configwork.EncodeURI(definitions[0])
	if err != nil {
		return nil, err
	}
	starter, err := yaml.Marshal(map[string]any{"mixed-port": 7890, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning", "proxies": []any{clientMap(j)}, "proxy-groups": []any{map[string]any{"name": "PROXY", "type": "select", "proxies": []string{id}}}, "rules": []string{"MATCH,PROXY"}})
	if err != nil {
		return nil, err
	}
	switch format {
	case "uri", "url":
		return []byte(uri + "\n"), nil
	case "qr":
		return qrcode.Encode(uri, qrcode.Medium, 384)
	case "starter":
		return starter, nil
	case "client-bundle":
		return json.MarshalIndent(map[string]any{"kind": "lazyclash-client-bundle", "version": 1, "id": id, "recipe": j.Plan.Recipe, "core_version": j.Plan.Artifact.Version, "deployment_status": j.Phase, "last_verified_at": j.VerifiedAt, "observed_exit_ip": j.ObservedExitIP, "public_host": j.Plan.PublicHost, "public_port": j.Plan.PublicPort, "uri": uri, "mihomo": string(node), "starter": string(starter)}, "", "  ")
	case "admin", "admin-bundle":
		if err = checkHost(j, o); err != nil {
			return nil, err
		}
		backup, err := execute(ctx, j.Host.SSHHost, remote(j, "backup"), o)
		if err != nil {
			return nil, err
		}
		if j.Plan.Recipe != "vless-reality" && (backup.CertificateFiles["fullchain.pem"] == "" || backup.CertificateFiles["privkey.pem"] == "") {
			return nil, errors.New("administrator backup could not include the issued TLS certificate and key")
		}
		return json.MarshalIndent(map[string]any{"kind": "lazyclash-administrator-backup", "version": 1, "deployment": j, "certificate_files": backup.CertificateFiles, "restoration": "Contains the pinned artifact references, server configuration, deployment ownership token, client credentials and issued TLS files. Cloud login credentials and SSH private keys are excluded."}, "", "  ")
	default:
		return nil, errors.New("export format must be uri, qr, yaml, starter, client-bundle or admin-bundle")
	}
}
