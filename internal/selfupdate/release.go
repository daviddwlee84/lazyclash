package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const releasesEndpoint = "https://api.github.com/repos/daviddwlee84/lazyclash/releases/latest"

func latestRelease(ctx context.Context) (Release, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	return fetchLatestRelease(ctx, client, releasesEndpoint)
}

func fetchLatestRelease(ctx context.Context, client *http.Client, endpoint string) (Release, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Release{}, errors.New("cannot construct release request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "lazyclash-upgrade")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Release{}, ctx.Err()
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return Release{}, fmt.Errorf("query latest release: %w", context.DeadlineExceeded)
		}
		// A transport error can embed proxy credentials or an untrusted URL.
		return Release{}, errors.New("query latest release failed; check network and proxy settings")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
			return Release{}, fmt.Errorf("GitHub release lookup was denied or rate limited (HTTP %d); retry later", response.StatusCode)
		}
		return Release{}, fmt.Errorf("GitHub release lookup failed (HTTP %d)", response.StatusCode)
	}
	const limit = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return Release{}, ctx.Err()
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return Release{}, fmt.Errorf("read latest release: %w", context.DeadlineExceeded)
		}
		return Release{}, errors.New("cannot read GitHub release response")
	}
	if len(body) > limit {
		return Release{}, errors.New("GitHub release response exceeded the size limit")
	}
	var data struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.Draft || data.Prerelease || !StableVersion(data.Tag) {
		return Release{}, errors.New("GitHub did not return a valid stable lazyclash release")
	}
	return Release{Version: data.Tag, URL: "https://github.com/daviddwlee84/lazyclash/releases/tag/" + data.Tag}, nil
}
