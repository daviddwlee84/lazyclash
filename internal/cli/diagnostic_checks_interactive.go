package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

// The dashboard releases its terminal to this same CLI workflow. Entering the
// menu only reads saved definitions; requests need an explicit Run selection.
func (o *options) runDiagnosticChecksInteractive(cmd *cobra.Command) error {
	if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
		return usage("--interactive requires a terminal and cannot use --json")
	}
	cfg, _, index, err := o.savedDiagnosticChecks(cmd)
	if err != nil {
		return err
	}
	target := cfg.Targets[index]
	choice, err := wizard.Choose(cmd.Context(), "Saved connectivity checks · "+core.Sanitize(target.ID), savedCheckMenuChoices(len(target.Checks), o.readOnly), cmd.InOrStdin(), cmd.OutOrStdout())
	if err != nil {
		return err
	}
	switch choice {
	case "list":
		if len(target.Checks) == 0 {
			message := "No saved connectivity checks on this target."
			if !o.readOnly {
				message += " Choose Add a saved check to create one; saving does not send a request."
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), message)
			return err
		}
		return o.output(cmd, map[string]any{"target_id": target.ID, "checks": target.Checks})
	case "run-all":
		return o.runSavedDiagnosticChecks(cmd, "", true)
	case "add":
		return o.editSavedDiagnosticCheck(cmd, config.DiagnosticCheck{}, false)
	}
	choices := make([]wizard.Choice, 0, len(target.Checks))
	for _, check := range target.Checks {
		label := check.ID
		if check.Name != "" {
			label += " · " + check.Name
		}
		choices = append(choices, wizard.Choice{Value: check.ID, Label: core.Sanitize(label)})
	}
	id, err := wizard.Choose(cmd.Context(), "Choose saved check · "+core.Sanitize(target.ID), choices, cmd.InOrStdin(), cmd.OutOrStdout())
	if err != nil {
		return err
	}
	for _, check := range target.Checks {
		if check.ID != id {
			continue
		}
		switch choice {
		case "run":
			return o.runSavedDiagnosticChecks(cmd, id, false)
		case "edit":
			return o.editSavedDiagnosticCheck(cmd, check, true)
		case "remove":
			accepted, e := wizard.Confirm(cmd.Context(), "Remove saved connectivity check", "Target: "+core.Sanitize(target.ID)+"\nCheck: "+core.Sanitize(check.ID)+"\nURL: "+core.Sanitize(check.URL), cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			if !accepted {
				return wizard.ErrCanceled
			}
			return o.removeSavedDiagnosticCheck(cmd, id)
		}
	}
	return usage("saved check selection is unavailable; reopen the checks menu")
}

func savedCheckMenuChoices(count int, readOnly bool) []wizard.Choice {
	choices := []wizard.Choice{{Value: "list", Label: "Review saved checks"}}
	if count > 0 && !readOnly {
		choices = append(choices, wizard.Choice{Value: "run-all", Label: "Run all saved checks"}, wizard.Choice{Value: "run", Label: "Run one saved check"})
	}
	if !readOnly {
		choices = append(choices, wizard.Choice{Value: "add", Label: "Add a saved check"})
		if count > 0 {
			choices = append(choices, wizard.Choice{Value: "edit", Label: "Edit a saved check"}, wizard.Choice{Value: "remove", Label: "Remove a saved check"})
		}
	}
	return choices
}

func savedCheckFields(check config.DiagnosticCheck, editing bool) []wizard.Field {
	fields := []wizard.Field{}
	if !editing {
		fields = append(fields, wizard.Field{Key: "id", Label: "Check ID", Value: check.ID, Required: true, Help: "A short reusable name, for example claude."})
	}
	fields = append(fields,
		wizard.Field{Key: "name", Label: "Display name (optional)", Value: check.Name},
		wizard.Field{Key: "url", Label: "Public HTTP(S) URL", Value: check.URL, Required: true, Help: "No login, query parameters or URL fragments; credentials are not stored."},
		wizard.Field{Key: "statuses", Label: "Expected HTTP statuses (comma separated; blank = 200–399)", Value: savedCheckStatuses(check.ExpectedStatuses)},
		wizard.Field{Key: "via", Label: "Comparison policy (optional)", Value: check.Via, Help: "Adds a core URLTest comparison. The HTTP check still follows the target's current routing."},
	)
	return fields
}

func (o *options) editSavedDiagnosticCheck(cmd *cobra.Command, check config.DiagnosticCheck, editing bool) error {
	if err := o.writable(); err != nil {
		return err
	}
	fields := savedCheckFields(check, editing)
	title := "Add saved connectivity check"
	if editing {
		title = "Edit saved connectivity check · " + core.Sanitize(check.ID)
	}
	const description = "Save a reusable check for this target. Requests run only when you choose Run. Browser login and application access are not tested."
	help := description
	for {
		values, err := wizard.Edit(cmd.Context(), wizard.Spec{Title: title, Description: help, SubmitLabel: "Save check", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		for i := range fields {
			fields[i].Value = values[fields[i].Key]
		}
		candidate := check
		if !editing {
			candidate.ID = strings.TrimSpace(values["id"])
		}
		candidate.Name, candidate.URL, candidate.Via = strings.TrimSpace(values["name"]), strings.TrimSpace(values["url"]), strings.TrimSpace(values["via"])
		candidate.ExpectedStatuses, err = parseSavedCheckStatuses(values["statuses"])
		if err == nil {
			err = config.ValidateDiagnosticChecks([]config.DiagnosticCheck{candidate})
		}
		if err != nil {
			help = core.Sanitize(err.Error()) + "\n" + description
			continue
		}
		return o.upsertSavedDiagnosticCheck(cmd, candidate, editing)
	}
}

func savedCheckStatuses(statuses []int) string {
	values := make([]string, len(statuses))
	for i, value := range statuses {
		values[i] = strconv.Itoa(value)
	}
	return strings.Join(values, ",")
}

func parseSavedCheckStatuses(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var statuses []int
	seen := map[int]bool{}
	for _, part := range strings.Split(value, ",") {
		status, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || status < 100 || status > 599 || seen[status] {
			return nil, usage("expected statuses must be distinct HTTP status codes from 100 to 599, separated by commas")
		}
		seen[status] = true
		statuses = append(statuses, status)
	}
	return statuses, nil
}
