package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/vps"
)

func TestVPSCatalogJSONAndCreateSyntax(t *testing.T) {
	var output bytes.Buffer
	cmd := New(Dependencies{})
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"vps", "catalog", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var entries []vps.Offering
	if err := json.Unmarshal(output.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) < 5 {
		t.Fatal("missing providers")
	}
	for _, entry := range entries {
		if entry.Source == "" || entry.Checked == "" || entry.TransferUnit == "" {
			t.Fatalf("incomplete catalog evidence: %#v", entry)
		}
	}
	for _, args := range [][]string{{"vps", "create", "--json"}, {"vps", "create", "--name", "partial"}, {"vps", "create", "--interactive", "--provider", "typo"}, {"vps", "create", "id", "--provider", "digitalocean", "--region", "sgp1", "--ssh-key", "key", "--yes"}} {
		t.Run(args[len(args)-1], func(t *testing.T) {
			calls := 0
			cmd := New(Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, VPS: vps.Options{Run: func(context.Context, string, []string) ([]byte, error) { calls++; return nil, nil }}})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(args)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := cmd.ExecuteContext(ctx)
			if err == nil || ExitCode(err) != 2 {
				t.Fatalf("invalid invocation should be a usage error: %v", err)
			}
			if calls != 0 {
				t.Fatal("invalid syntax contacted provider")
			}
		})
	}
}
