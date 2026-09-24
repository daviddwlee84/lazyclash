package configwork

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type ConfigDiffTarget struct {
	TargetID string      `json:"target"`
	Status   string      `json:"status"`
	Message  string      `json:"message,omitempty"`
	Diff     *ConfigDiff `json:"diff,omitempty"`
}

type ConfigDiffReport struct {
	SourceTargetID string             `json:"source_target_id"`
	Status         string             `json:"status"`
	Targets        []ConfigDiffTarget `json:"targets"`
	Warnings       []string           `json:"warnings,omitempty"`
}

// DiffConfigs reads persistent declarations, independently of runtime metadata.
// A missing source is never represented as an empty configuration or equality.
func DiffConfigs(ctx context.Context, baseline config.Target, targets []config.Target, opts Options) (ConfigDiffReport, error) {
	r := ConfigDiffReport{SourceTargetID: baseline.ID, Status: "complete", Targets: []ConfigDiffTarget{}}
	opts.ReadOnly = true
	source, err := SnapshotConfig(ctx, baseline, opts)
	if err != nil {
		r.Status = "blocked"
		return r, fmt.Errorf("source %q: %w", baseline.ID, err)
	}
	r.Warnings = source.Warnings
	var failures []error
	available := 0
	for _, target := range targets {
		if err = ctx.Err(); err != nil {
			return r, err
		}
		item := ConfigDiffTarget{TargetID: target.ID, Status: "available"}
		dest, e := SnapshotConfig(ctx, target, opts)
		if e != nil {
			item.Status, item.Message = "error", core.Sanitize(e.Error())
			if errors.Is(e, ErrConfigUnavailable) {
				item.Status = "unavailable"
				r.Status = "completed_with_skips"
			} else {
				failures = append(failures, fmt.Errorf("target %q: %w", target.ID, e))
			}
		} else {
			diff := CompareConfig(source, dest)
			item.Diff = &diff
			available++
		}
		r.Targets = append(r.Targets, item)
	}
	if available == 0 && len(failures) == 0 {
		failures = append(failures, errors.New("no destination configuration was available to compare"))
	}
	if len(failures) > 0 {
		r.Status = "blocked"
	}
	return r, errors.Join(failures...)
}

func FormatConfigDiffReport(r ConfigDiffReport, format string) string {
	var b strings.Builder
	for _, target := range r.Targets {
		fmt.Fprintf(&b, "%s → %s [%s]\n", r.SourceTargetID, target.TargetID, target.Status)
		if target.Message != "" {
			fmt.Fprintln(&b, target.Message)
		}
		if target.Diff != nil {
			fmt.Fprint(&b, FormatConfigDiff(*target.Diff, format))
		}
		fmt.Fprintln(&b)
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return core.Sanitize(b.String())
}
