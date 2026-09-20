package compare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func validateSelection(selection Selection) (Selection, error) {
	selection.Fields = uniqueSorted(selection.Fields)
	selection.Groups = uniqueSorted(selection.Groups)
	if len(selection.Fields) == 0 && len(selection.Groups) == 0 {
		return selection, invalid("select at least one field (mode or log-level) or manual Selector group")
	}
	for _, field := range selection.Fields {
		if field != "mode" && field != "log-level" {
			return selection, invalid("field %q cannot be copied; allowed fields are mode and log-level", field)
		}
	}
	for _, group := range selection.Groups {
		if group == "" {
			return selection, invalid("group name cannot be empty")
		}
	}
	return selection, nil
}

// Preview is read-only even when Options.ReadOnly is false. Its digest binds
// the target identities, reported core versions, explicit selection, field
// values and selected groups' types/member sets/manual choices.
func Preview(ctx context.Context, source, destination config.Target, selection Selection, opts Options) (Plan, error) {
	var err error
	selection, err = validateSelection(selection)
	if err != nil {
		return Plan{}, err
	}
	if err := validatePair(source, destination); err != nil {
		return Plan{}, err
	}
	src, err := open(ctx, source, true, opts)
	if err != nil {
		return Plan{}, err
	}
	defer src.close()
	dst, err := open(ctx, destination, true, opts)
	if err != nil {
		return Plan{}, err
	}
	defer dst.close()
	return planFromClients(ctx, src.client, dst.client, source, destination, selection)
}

func planFromClients(ctx context.Context, src, dst *core.Client, source, destination config.Target, selection Selection) (Plan, error) {
	a, err := read(ctx, src, source)
	if err != nil {
		return Plan{}, err
	}
	b, err := read(ctx, dst, destination)
	if err != nil {
		return Plan{}, err
	}
	return makePlan(a, b, selection)
}

func makePlan(source, destination Snapshot, selection Selection) (Plan, error) {
	plan := Plan{Source: source.Target, Destination: destination.Target, Selection: selection, Steps: []Step{}, SourceVersion: source.Version, DestinationVersion: destination.Version}
	fields := map[string]Step{}
	for _, field := range selection.Fields {
		a, aOK := source.General[field].(string)
		b, bOK := destination.General[field].(string)
		if !aOK || !bOK || !validField(field, a) || !validField(field, b) {
			return plan, invalid("both targets must report a supported %s value before copying it", field)
		}
		fields[field] = Step{Kind: "field", Name: field, Before: b, After: a, Changed: a != b}
	}
	// Keep mode last: a mode change may affect traffic before the selected
	// destination groups are ready. Logging first helps inspect later failures.
	if step, ok := fields["log-level"]; ok {
		plan.Steps = append(plan.Steps, step)
	}
	left, right := groupsByName(source.Groups), groupsByName(destination.Groups)
	var sourceGroups, destinationGroups []Group
	for _, name := range selection.Groups {
		a, aOK := left[name]
		b, bOK := right[name]
		if !aOK || !bOK {
			return plan, invalid("group %q must exist on both targets", name)
		}
		if !strings.EqualFold(a.Type, "Selector") || !strings.EqualFold(b.Type, "Selector") {
			return plan, invalid("group %q must be a manual Selector on both targets; automatic selections are not copied", name)
		}
		if a.Selected == "" || !slices.Contains(a.Members, a.Selected) || !slices.Contains(b.Members, a.Selected) {
			return plan, invalid("source selection for group %q must be a member on both targets", name)
		}
		if b.Selected == "" || !slices.Contains(b.Members, b.Selected) {
			return plan, invalid("destination group %q has no valid reported manual selection", name)
		}
		sourceGroups, destinationGroups = append(sourceGroups, a), append(destinationGroups, b)
		plan.Steps = append(plan.Steps, Step{Kind: "group", Name: name, Before: b.Selected, After: a.Selected, Changed: a.Selected != b.Selected, DestinationMembers: b.Members})
	}
	if step, ok := fields["mode"]; ok {
		plan.Steps = append(plan.Steps, step)
	}
	encoded, err := json.Marshal(struct {
		SchemaVersion      int     `json:"schema_version"`
		Plan               Plan    `json:"plan"`
		SourceVersion      string  `json:"source_version"`
		DestinationVersion string  `json:"destination_version"`
		SourceGroups       []Group `json:"source_groups"`
		DestinationGroups  []Group `json:"destination_groups"`
	}{1, plan, source.Version, destination.Version, sourceGroups, destinationGroups})
	if err != nil {
		return plan, fmt.Errorf("encode copy preview: %w", err)
	}
	digest := sha256.Sum256(encoded)
	plan.Digest = hex.EncodeToString(digest[:])
	return plan, nil
}

func validField(field, value string) bool {
	switch field {
	case "mode":
		return slices.Contains([]string{"rule", "global", "direct"}, value)
	case "log-level":
		return slices.Contains([]string{"debug", "info", "warning", "error", "silent"}, value)
	}
	return false
}

// Apply rereads both targets and validates the complete selected plan before
// sending any mutation. It stops on the first failure, preserves a per-step
// receipt and never retries or rolls back a possibly accepted write.
func Apply(ctx context.Context, source, destination config.Target, selection Selection, expectDigest string, opts Options) (ApplyResult, error) {
	result := ApplyResult{Status: "preflight", Steps: []StepResult{}}
	if opts.ReadOnly {
		return result, &core.Error{Kind: core.KindReadOnly, Operation: "copy runtime settings"}
	}
	decoded, err := hex.DecodeString(expectDigest)
	if err != nil || len(decoded) != sha256.Size {
		return result, invalid("applying requires the 64-character digest from a copy-settings preview")
	}
	expectDigest = strings.ToLower(expectDigest)
	selection, err = validateSelection(selection)
	if err != nil {
		return result, err
	}
	if err := validatePair(source, destination); err != nil {
		return result, err
	}
	src, err := open(ctx, source, true, opts)
	if err != nil {
		return result, err
	}
	defer src.close()
	dst, err := open(ctx, destination, false, opts)
	if err != nil {
		return result, err
	}
	defer dst.close()
	result.Plan, err = planFromClients(ctx, src.client, dst.client, source, destination, selection)
	if err != nil {
		return result, err
	}
	if result.Plan.Digest != expectDigest {
		result.Status = "stale"
		return result, ErrStale
	}
	for _, step := range result.Plan.Steps {
		result.Steps = append(result.Steps, StepResult{Step: step, Status: "pending"})
	}
	for i, step := range result.Plan.Steps {
		if err := ctx.Err(); err != nil {
			result.Status = "stopped"
			return result, err
		}
		// Recheck each destination value immediately before writing. The API
		// offers no conditional writes; this narrows, but cannot eliminate,
		// races with another controller after the all-fields preflight.
		if err := checkDestination(ctx, dst.client, step); err != nil {
			result.Status = "stopped"
			result.Steps[i].Status, result.Steps[i].Error = "failed", safeError(err)
			return result, err
		}
		if !step.Changed {
			result.Steps[i].Status = "unchanged"
			continue
		}
		if step.Kind == "group" {
			err = dst.client.Select(ctx, step.Name, step.After)
		} else {
			_, err = dst.client.SetConfig(ctx, core.Object{step.Name: step.After})
		}
		if err != nil {
			result.Status = "stopped"
			status := "failed"
			var coreError *core.Error
			if errors.As(err, &coreError) && coreError.Kind == core.KindUnknownWrite {
				status = "unknown"
			}
			result.Steps[i].Status, result.Steps[i].Error = status, safeError(err)
			return result, fmt.Errorf("copy %s %q stopped; inspect destination before another apply: %w", step.Kind, step.Name, err)
		}
		result.Steps[i].Status = "applied"
	}
	result.Status = "applied"
	return result, nil
}

func checkDestination(ctx context.Context, client *core.Client, step Step) error {
	if step.Kind == "group" {
		proxies, err := client.Proxies(ctx)
		if err != nil {
			return err
		}
		group, ok := proxies[step.Name]
		if !ok || !strings.EqualFold(group.Type, "Selector") || group.Now != step.Before || !slices.Equal(uniqueSorted(group.All), step.DestinationMembers) || !slices.Contains(group.All, step.After) {
			return ErrStale
		}
		return nil
	}
	settings, err := client.Config(ctx)
	if err != nil {
		return err
	}
	if actual, ok := settings[step.Name].(string); !ok || actual != step.Before {
		return ErrStale
	}
	return nil
}

func safeError(err error) string {
	return strings.Join(strings.Fields(core.Sanitize(err.Error())), " ")
}
