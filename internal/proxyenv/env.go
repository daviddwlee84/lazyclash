package proxyenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

var Variables = []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"}
var EnvironmentVariables = append(append([]string{}, Variables...), OriginVariable)

func credential(p Plan) (string, error) {
	var password string
	if p.PasswordEnv != "" {
		var ok bool
		password, ok = os.LookupEnv(p.PasswordEnv)
		if !ok {
			return "", errors.New("proxy password environment variable is not set")
		}
	}
	if p.PasswordFile != "" {
		f, e := os.Open(p.PasswordFile)
		if e != nil {
			return "", errors.New("cannot read proxy password file")
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() {
			return "", errors.New("proxy password must be a regular file")
		}
		b, e := io.ReadAll(io.LimitReader(f, 65537))
		if e != nil || len(b) > 65536 {
			return "", errors.New("proxy password file exceeds limit")
		}
		password = strings.TrimRight(string(b), "\r\n")
	}
	if len(password) > 65536 || strings.IndexFunc(password, unicode.IsControl) >= 0 {
		return "", errors.New("invalid proxy password")
	}
	return password, nil
}

// Values resolves credentials only at the process boundary. Callers must not
// log, persist, or include this map in ordinary status/JSON output.
func Values(p Plan) (map[string]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.SSHHost != "" {
		return nil, ErrRemoteEnv
	}
	password, err := credential(p)
	if err != nil {
		return nil, err
	}
	withAuth := func(raw string) string {
		u, _ := url.Parse(raw)
		if p.Username != "" || p.PasswordEnv != "" || p.PasswordFile != "" {
			u.User = url.UserPassword(p.Username, password)
		}
		return u.String()
	}
	http, all := withAuth(p.HTTP), withAuth(p.All)
	origin, err := environmentOrigin(p)
	if err != nil {
		return nil, err
	}
	return map[string]string{"http_proxy": http, "https_proxy": http, "HTTP_PROXY": http, "HTTPS_PROXY": http, "all_proxy": all, "ALL_PROXY": all, OriginVariable: origin}, nil
}

func Quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func RenderEnv(p Plan, shell string) (string, error) {
	if shell != "bash" && shell != "zsh" && shell != "sh" {
		return "", errors.New("supported shells: bash, zsh, sh")
	}
	values, err := Values(p)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, key := range EnvironmentVariables {
		fmt.Fprintf(&out, "export %s=%s\n", key, Quote(values[key]))
	}
	return out.String(), nil
}

func ChildEnvironment(base []string, values map[string]string) []string {
	out := make([]string, 0, len(base)+len(values))
	var previousOrigin string
	for _, entry := range base {
		key, value, _ := strings.Cut(entry, "=")
		if key == OriginVariable {
			previousOrigin = value
		}
	}
	keepSession := values[OriginVariable] != "" && values[OriginVariable] == previousOrigin
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if key == "LAZYCLASH_PROXY_SESSION" && !keepSession {
			continue
		}
		if _, replace := values[key]; !replace {
			out = append(out, entry)
		}
	}
	for _, key := range EnvironmentVariables {
		if value, ok := values[key]; ok {
			out = append(out, key+"="+value)
		}
	}
	return out
}

func Exec(ctx context.Context, p Plan, argv []string, in io.Reader, out, errOut io.Writer) error {
	if len(argv) == 0 {
		return errors.New("proxy exec requires a command after --")
	}
	values, err := Values(p)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = ChildEnvironment(os.Environ(), values)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
	configureChild(cmd)
	err = cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		code := exited.ExitCode()
		if code < 0 {
			code = signalExitCode(exited)
		}
		return &ExitError{Code: code}
	}
	if err != nil {
		return errors.New("cannot start child command")
	}
	return nil
}
