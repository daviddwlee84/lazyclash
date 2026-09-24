package configwork

import (
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
)

var dockerScript = sourceowner.DockerHostScript()

type dockerInfo = sourceowner.DockerInfo

func dockerCall(ctx context.Context, t config.Target, op string, data []byte, version string) (dockerInfo, error) {
	s := t.ConfigSource
	req := sourceowner.DockerRequest{DockerSource: sourceowner.DockerSource{DockerHost: s.DockerHost, Container: s.Container, HostPath: s.HostPath, CorePath: s.CorePath, Binary: s.Binary, Home: s.Home}, Op: op, Version: version}
	if data != nil {
		n, e := decode(data)
		if e != nil {
			return dockerInfo{}, e
		}
		if n.Decode(&req.Document) != nil {
			return dockerInfo{}, errors.New("invalid validation document")
		}
	}
	return sourceowner.DockerOperation(ctx, t.SSHHost, req)
}
