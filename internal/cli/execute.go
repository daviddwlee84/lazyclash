package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Execute is the process boundary: stdout belongs to command data; errors are
// rendered exactly once on stderr after command resources have been released.
func Execute(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	return execute(ctx, args, in, out, errOut, Dependencies{})
}

func execute(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, deps Dependencies) int {
	cmd := New(deps)
	cmd.SetArgs(append([]string{}, args...))
	cmd.SetIn(in)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	jsonMode := jsonRequested(cmd, args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		if jsonMode {
			encoder := json.NewEncoder(errOut)
			encoder.SetEscapeHTML(false)
			_ = encoder.Encode(errorEnvelope{Error: describeError(err)})
		} else {
			_, _ = fmt.Fprintln(errOut, "lazyclash:", core.Sanitize(err.Error()))
		}
		return ExitCode(err)
	}
	return 0
}

type errorEnvelope struct {
	Error errorDetails `json:"error"`
}

type errorDetails struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Operation  string `json:"operation,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

func describeError(err error) errorDetails {
	result := errorDetails{Code: "runtime", Message: core.Sanitize(err.Error())}
	var controllerErr *core.Error
	var usageErr *UsageError
	var proxyAmbiguous *proxyenv.AmbiguousError
	switch {
	case errors.As(err, &controllerErr):
		// Preserve unknown-write-result even when its cause is cancellation.
		result.Code = string(controllerErr.Kind)
		result.Operation = controllerErr.Operation
		result.HTTPStatus = controllerErr.StatusCode
	case errors.As(err, &usageErr), strings.HasPrefix(err.Error(), "unknown command "):
		result.Code = "usage"
	case connection.IsAuthRequired(err):
		result.Code = "ssh-auth-required"
	case errors.As(err, &proxyAmbiguous):
		result.Code = "proxy-target-ambiguous"
	case errors.Is(err, proxyenv.ErrNoProxyConfigured):
		result.Code = "proxy-not-configured"
	case errors.Is(err, proxyenv.ErrTemporaryProxy):
		result.Code = "proxy-temporary"
	case errors.Is(err, config.ErrConflict), errors.Is(err, serverstate.ErrConflict):
		result.Code = "config-conflict"
	case errors.Is(err, context.Canceled), errors.Is(err, wizard.ErrCanceled):
		result.Code = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		result.Code = "timeout"
	}
	return result
}

// Inspect output intent before execution so syntax errors can also be JSON.
// Respect flag values and the -- terminator instead of finding a substring in
// argv (a filename or filter value may itself be "--json"). Cobra remains the
// authority for syntax/argument validation.
func jsonRequested(root *cobra.Command, args []string) bool {
	valueFlags := map[string]bool{}
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		for _, flags := range []*pflag.FlagSet{cmd.LocalNonPersistentFlags(), cmd.PersistentFlags()} {
			flags.VisitAll(func(flag *pflag.Flag) {
				if flag.NoOptDefVal == "" {
					valueFlags["--"+flag.Name] = true
					if flag.Shorthand != "" {
						valueFlags["-"+flag.Shorthand] = true
					}
				}
			})
		}
		for _, child := range cmd.Commands() {
			visit(child)
		}
	}
	visit(root)
	requested := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if name == "--json" {
			if !hasValue {
				requested = true
			} else if parsed, err := strconv.ParseBool(value); err == nil {
				requested = parsed
			}
			continue
		}
		if !hasValue && valueFlags[name] {
			i++
		}
	}
	return requested
}
