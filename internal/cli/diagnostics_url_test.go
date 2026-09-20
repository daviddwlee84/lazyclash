package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func TestDiagnosticURLCLIObserveOnlyJSONAndNoPersistence(t *testing.T) {
	path := isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "test", "--controller", server.URL); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, Dependencies{}, "--read-only", "diagnostics", "url", "https://example.invalid/path?token=PRIVATE", "--observe-only", "--json")
	var result diagnostics.URLResult
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || !result.ObserveOnly || result.URL != "https://example.invalid/path" {
		t.Fatalf("result=%s err=%v", out, err)
	}
	if strings.Contains(out, "PRIVATE") {
		t.Fatal("query leaked")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("diagnostic wrote preferences")
	}
	out, _, err = run(t, Dependencies{}, "--read-only", "diagnostics", "url", "https://example.invalid/", "--json")
	if err == nil || out != "" || ExitCode(err) != 2 {
		t.Fatalf("readonly active command=%s error=%v", out, err)
	}
	out, _, err = run(t, Dependencies{}, "diagnostics", "url", "https://user:PRIVATE@example.invalid/", "--observe-only", "--json")
	if err == nil || out != "" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("credential URL accepted/leaked: %s %v", out, err)
	}
}
