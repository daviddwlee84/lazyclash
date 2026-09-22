package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Requests contain arguments, never shell commands. Paths and target IDs are
// resolved by the remote binary on the collecting host.
const analyticsRemoteHelper = `import json,os,shutil,subprocess,sys
r=json.load(sys.stdin)
binary=r.get("binary") or "lazyclash"
if not isinstance(binary,str) or any(ord(c)<32 for c in binary):
    raise SystemExit("invalid executable")
binary=shutil.which(binary)
if not binary:
    print(json.dumps({"code":127,"stdout":"","error":"lazyclash is unavailable on the collector host; supply --remote-binary"})); sys.exit(0)
args=r["args"]
if not isinstance(args,list) or not args or args[0]!="analytics" or any(not isinstance(x,str) or "\x00" in x for x in args):
    raise SystemExit("invalid request")
import tempfile
with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
    p=subprocess.Popen([binary]+args,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
    try:
        import time
        deadline=time.monotonic()+90
        while p.poll() is None:
            if time.monotonic()>deadline:
                p.kill(); p.wait()
                print(json.dumps({"code":124,"stdout":"","error":"remote command timed out; inspect state before retrying a mutation"}));sys.exit(0)
            if os.fstat(out.fileno()).st_size>8388608 or os.fstat(err.fileno()).st_size>65536:
                p.kill(); p.wait(); raise RuntimeError("remote analytics output exceeded limit")
            time.sleep(0.05)
        out.seek(0); data=out.read(8388609)
        err.seek(0); diagnostic=err.read(65537)
        if len(data)>8388608 or len(diagnostic)>65536: raise RuntimeError("remote analytics output exceeded limit")
        message=""
        if p.returncode:
            try: message=json.loads(diagnostic.decode()).get("error",{}).get("message","")
            except Exception: pass
            if not message: message="remote analytics command failed"
        print(json.dumps({"code":p.returncode,"stdout":data.decode(),"error":message}))
    finally:
        if p.poll() is None: p.kill(); p.wait()
`

func remoteAnalytics(ctx context.Context, host, binary string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 95*time.Second)
	defer cancel()
	in, err := json.Marshal(map[string]any{"binary": binary, "args": append([]string{"analytics"}, args...)})
	if err != nil {
		return nil, err
	}
	out, err := connection.ExecutePython(ctx, host, analyticsRemoteHelper, in, 12<<20)
	if err != nil {
		return nil, err
	}
	var result struct {
		Code   int    `json:"code"`
		Stdout string `json:"stdout"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, errors.New("invalid remote analytics response")
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("remote analytics: %s", result.Error)
	}
	return []byte(result.Stdout), nil
}

// forward runs an already parsed non-interactive command using the selected
// collector host's settings, credentials, state and executable.
func (a *analyticsCLI) forward(cmd *cobra.Command) error {
	if flag := cmd.Flags().Lookup("interactive"); flag != nil && flag.Value.String() == "true" {
		return usage("remote setup is flag-driven; use report --interactive to browse a remote collector")
	}
	args := analyticsRemoteArgs(cmd)
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	out, err := remoteAnalytics(ctx, a.host, a.remoteBinary, args)
	if err != nil {
		return err
	}
	if a.o.json {
		_, err = cmd.OutOrStdout().Write(out)
		return err
	}
	if cmd.Name() == "report" {
		var report analytics.Report
		if err = json.Unmarshal(out, &report); err != nil {
			return errors.New("invalid remote analytics report")
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), tui.FormatAnalyticsReport(report))
		return err
	}
	var value any
	if err = json.Unmarshal(out, &value); err != nil {
		return errors.New("remote analytics returned invalid JSON")
	}
	return a.o.output(cmd, value)
}

func analyticsRemoteArgs(cmd *cobra.Command) []string {
	parts := strings.Fields(cmd.CommandPath())
	args := append([]string(nil), parts[2:]...)
	seen := map[string]bool{}
	add := func(f *pflag.Flag) {
		if seen[f.Name] || !f.Changed {
			return
		}
		seen[f.Name] = true
		switch f.Name {
		case "collector-host", "remote-binary", "json", "interactive":
			return
		}
		value := f.Value.String()
		if slice, ok := f.Value.(pflag.SliceValue); ok {
			var buffer bytes.Buffer
			writer := csv.NewWriter(&buffer)
			_ = writer.Write(slice.GetSlice())
			writer.Flush()
			value = strings.TrimSuffix(buffer.String(), "\n")
		}
		args = append(args, "--"+f.Name+"="+value)
	}
	cmd.Flags().VisitAll(add)
	cmd.InheritedFlags().VisitAll(add)
	args = append(args, "--json")
	return args
}
