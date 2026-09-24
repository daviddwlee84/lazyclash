package rulework

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/clientservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
)

var ErrSourceUnavailable = errors.New("persistent rule source is unavailable")

func ruleDockerSource(t config.Target) sourceowner.DockerSource {
	s := t.RuleSource
	return sourceowner.DockerSource{DockerHost: s.DockerHost, Container: s.Container, HostPath: s.HostPath, CorePath: s.CorePath, Binary: s.Binary, Home: s.Home}
}

func ruleDockerOperation(ctx context.Context, t config.Target, op string, document any, version string, opts Options) (DockerInfo, error) {
	req := DockerRequest{DockerSource: ruleDockerSource(t), Op: op, Document: document, Version: version}
	var info DockerInfo
	var err error
	if opts.Docker != nil {
		info, err = opts.Docker(ctx, t, req)
	} else if t.ManagedCoreID != "" {
		return DockerInfo{}, errors.New("managed Docker rule source requires its owned host adapter")
	} else {
		info, err = sourceowner.DockerOperation(ctx, t.SSHHost, req)
	}
	var transport *connection.SSHTransportError
	var authentication *connection.AuthRequiredError
	if errors.Is(err, sourceowner.ErrUnavailable) || errors.As(err, &transport) || errors.As(err, &authentication) {
		return info, fmt.Errorf("%w: %w", ErrSourceUnavailable, err)
	}
	return info, err
}

func sourceReloadPath(s Source) string {
	if s.applyPath != "" {
		return s.applyPath
	}
	return s.File
}

func sourceOwnerIdentity(s Source) string {
	if s.dockerInfo.ContainerID == "" {
		return ""
	}
	return s.dockerInfo.ContainerID + ":" + s.dockerInfo.Image
}

func validateOwnerCandidate(ctx context.Context, t config.Target, source Source, data []byte, version string, opts Options) error {
	return validateOwnerCandidateVisibility(ctx, t, source, data, version, opts, true)
}

// A receipt-guarded rollback may restore the previous source while the owner
// still sees those previous bytes through an unrefreshed single-file mount.
func validateOwnerRestoreCandidate(ctx context.Context, t config.Target, source Source, data []byte, version string, opts Options) error {
	return validateOwnerCandidateVisibility(ctx, t, source, data, version, opts, false)
}

func validateOwnerCandidateVisibility(ctx context.Context, t config.Target, source Source, data []byte, version string, opts Options, requireVisible bool) error {
	if source.Kind == "verge" {
		return nil
	}
	if requireVisible && source.Kind == "docker" && source.dockerInfo.SourceSHA256 != source.file.SHA256 {
		return errors.New("container source differs from host source; recover owner activation before another change")
	}
	if opts.Validate != nil {
		return opts.Validate(ctx, t, data, version)
	}
	if source.Kind != "docker" {
		return validateCandidateWithOptions(ctx, t, data, version, ValidationSandbox{DockerHost: t.RuleSource.ValidationDockerHost, Image: t.RuleSource.ValidationImage}, opts)
	}
	node, err := decodeYAML(data)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err = node.Decode(&doc); err != nil {
		return errors.New("cannot prepare isolated Docker validation document")
	}
	info, err := ruleDockerOperation(ctx, t, "validate", doc, version, opts)
	if err == nil && (info.ContainerID != source.dockerInfo.ContainerID || info.Image != source.dockerInfo.Image) {
		return errors.New("Docker owner changed during validation; prepare a new preview")
	}
	if requireVisible && err == nil && info.SourceSHA256 != source.file.SHA256 {
		return errors.New("container source changed during validation; prepare a new preview")
	}
	return err
}

// Only read readiness is retried after a confirmed owner restart. Callers send
// the subsequent reload once, preserving unknown-write semantics.
func waitForOwnerCore(ctx context.Context, t config.Target, opts Options) error {
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		client, cleanup, err := openCore(readyCtx, t, true, opts)
		if err == nil {
			_, err = client.Version(readyCtx)
			cleanup()
		}
		if err == nil {
			return nil
		}
		select {
		case <-readyCtx.Done():
			return fmt.Errorf("restarted controller readiness was not observed: %w", readyCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// activateOwnerSource proves that an owner sees the saved bytes before reload.
// ready=false with no error leaves activation to the explicitly bound owner.
func activateOwnerSource(ctx context.Context, t config.Target, source Source, sum string, opts Options) (ready, restarted bool, err error) {
	if opts.ReadOnly {
		return false, false, errors.New("owner activation is disabled in read-only mode")
	}
	if source.Kind != "docker" {
		return true, false, nil
	}
	info, err := ruleDockerOperation(ctx, t, "inspect", nil, "", opts)
	if err != nil {
		return false, false, err
	}
	if info.ContainerID != source.dockerInfo.ContainerID || info.Image != source.dockerInfo.Image {
		return false, false, errors.New("Docker owner changed before runtime activation")
	}
	if info.SourceSHA256 == sum {
		return true, false, nil
	}
	if t.Service == nil {
		return false, false, nil
	}
	serviceOpts := opts.ClientServices
	serviceOpts.ReadOnly = opts.ReadOnly || serviceOpts.ReadOnly
	r, err := clientservice.RestartForBoundSource(ctx, t, ruleDockerSource(t), sum, serviceOpts)
	if err != nil {
		return false, r.ID != "", err
	}
	info, err = ruleDockerOperation(ctx, t, "inspect", nil, "", opts)
	if err != nil {
		return false, r.ID != "", err
	}
	if info.ContainerID != source.dockerInfo.ContainerID || info.Image != source.dockerInfo.Image || info.SourceSHA256 != sum {
		return false, r.ID != "", errors.New("Docker owner or visible source changed after activation")
	}
	return true, r.ID != "", nil
}
