package proxyenv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealShellSnapshotFunctionsFailureAndExitHooks(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			binary, err := exec.LookPath(shell)
			if err != nil {
				t.Skip(shell + " unavailable")
			}
			dir := t.TempDir()
			fake := filepath.Join(dir, "fake lazyclash")
			log := filepath.Join(dir, "calls")
			fakeScript := `#!/bin/sh
case "$1 $2 $3" in
 'proxy tunnel new-id') n=0; [ ! -f "$FIXTURE_COUNTER" ] || n=$(cat "$FIXTURE_COUNTER"); n=$((n+1)); printf '%s' "$n" > "$FIXTURE_COUNTER"; printf '%032d\n' "$n" ;;
 'proxy tunnel start') case "$*" in *fail*) exit 9;; esac; printf 'start\n' >> "$FIXTURE_LOG" ;;
 'proxy tunnel stop') printf 'stop:%s\n' "$4" >> "$FIXTURE_LOG" ;;
 'proxy env --session'|'proxy env --shell') printf '%s\n' "export http_proxy='http://fixture:7890'" "export https_proxy='http://fixture:7890'" "export HTTP_PROXY='http://fixture:7890'" "export HTTPS_PROXY='http://fixture:7890'" "export all_proxy='socks5h://fixture:7891'" "export ALL_PROXY='socks5h://fixture:7891'" "export LAZYCLASH_PROXY_ORIGIN='temporary-fixture'" ;;
 *) exit 0 ;;
esac
`
			if err := os.WriteFile(fake, []byte(fakeScript), 0700); err != nil {
				t.Fatal(err)
			}
			init, err := ShellInit(shell, fake, false)
			if err != nil {
				t.Fatal(err)
			}
			prior := `trap 'printf "prior:%s\n" "$?" >> "$FIXTURE_LOG"' EXIT` + "\n"
			if shell == "zsh" {
				prior = `autoload -Uz add-zsh-hook
prior_hook() { printf 'prior-zsh\n' >> "$FIXTURE_LOG"; }
add-zsh-hook zshexit prior_hook
`
			}
			script := prior + `proxy-on() { printf existing; }
export http_proxy="old'quoted"
unset ALL_PROXY
export NO_PROXY='preserve.local'
export LAZYCLASH_PROXY_ORIGIN='prior-origin'
` + init + `
[ "$(proxy-on)" = existing ] || exit 41
lazyclash-proxy-on --endpoint http://fixture:7890 || exit 42
[ "$http_proxy" = http://fixture:7890 ] || exit 43
[ "$NO_PROXY" = preserve.local ] || exit 44
[ "$LAZYCLASH_PROXY_ORIGIN" = temporary-fixture ] || exit 53
old_session=$LAZYCLASH_PROXY_SESSION
lazyclash-proxy-on --endpoint fail && exit 45
[ "$LAZYCLASH_PROXY_SESSION" = "$old_session" ] || exit 46
sample_function() { printf '%s' "$http_proxy"; }
[ "$(lazyclash-withproxy sample_function)" = http://fixture:7890 ] || exit 47
lazyclash-proxy-off || exit 48
[ "$http_proxy" = "old'quoted" ] || exit 49
[ "${ALL_PROXY+x}" != x ] || exit 50
[ "$NO_PROXY" = preserve.local ] || exit 51
[ "$LAZYCLASH_PROXY_ORIGIN" = prior-origin ] || exit 54
lazyclash-proxy-on --endpoint http://fixture:7890 || exit 52
exit 23
`
			file := filepath.Join(dir, "check.sh")
			os.WriteFile(file, []byte(script), 0600)
			args := []string{"--noprofile", "--norc", file}
			if shell == "zsh" {
				args = []string{"-f", file}
			}
			cmd := exec.Command(binary, args...)
			cmd.Env = append(os.Environ(), "FIXTURE_LOG="+log, "FIXTURE_COUNTER="+filepath.Join(dir, "counter"))
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 23 {
				t.Fatalf("shell contract: %s err=%v", out, err)
			}
			data, _ := os.ReadFile(log)
			if strings.Count(string(data), "stop:") != 2 {
				t.Fatalf("session cleanup: %s", data)
			}
			expected := "prior:23"
			if shell == "zsh" {
				expected = "prior-zsh"
			}
			if !strings.Contains(string(data), expected) {
				t.Fatalf("old exit hook lost: %s", data)
			}
		})
	}
}

func TestShellInitReplacementIsExplicit(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			if _, err := exec.LookPath(shell); err != nil {
				t.Skip("shell unavailable")
			}
			truePath, err := exec.LookPath("true")
			if err != nil {
				t.Fatal(err)
			}
			init, err := ShellInit(shell, truePath, true)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(shell, "-c", "proxy-status() { printf old; };\n"+init+"\nproxy-status")
			out, err := cmd.CombinedOutput()
			if err != nil || len(out) != 0 {
				t.Fatalf("replacement failed: %q %v", out, err)
			}
		})
	}
}

func ExampleShellInit() {
	fmt.Println(`eval "$(lazyclash proxy shell-init zsh)"`)
	// Output: eval "$(lazyclash proxy shell-init zsh)"
}
