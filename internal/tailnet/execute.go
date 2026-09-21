package tailnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

const stageScript = `import hashlib,json,os,pathlib,sys,tempfile
b=sys.stdin.buffer.read(2*1024*1024+1)
if len(b)>2*1024*1024: raise RuntimeError('request too large')
p=pathlib.Path.home()/'.cache/lazyclash/tailnet-requests'
p.mkdir(parents=True,exist_ok=True,mode=0o700)
if p.is_symlink() or p.stat().st_uid!=os.getuid() or p.stat().st_mode&0o077: raise RuntimeError('unsafe staging root')
f,name=tempfile.mkstemp(prefix='request-',suffix='.json',dir=p)
with os.fdopen(f,'wb') as w:w.write(b)
json.dump({'path':name,'sha256':hashlib.sha256(b).hexdigest()},sys.stdout)
`
const cleanupScript = `import json,os,pathlib,stat,sys
r=json.load(sys.stdin);p=pathlib.Path(r['path']);root=pathlib.Path.home()/'.cache/lazyclash/tailnet-requests'
if p.parent==root and p.name.startswith('request-'):
 try:
  s=p.lstat()
  if stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid():p.unlink()
 except FileNotFoundError:pass
`

// ExecuteHelper runs fixed Python with JSON on stdin. Privileged execution uses
// a private digest-checked staged request and native sudo; passwords never pass
// through Go. Scripts must print one JSON result and must not embed input code.
func ExecuteHelper(ctx context.Context, host, script string, input []byte, privileged bool, foreground func(*exec.Cmd) error) ([]byte, error) {
	if len(input) > 2<<20 {
		return nil, errors.New("tailnet helper request exceeds size limit")
	}
	if !privileged {
		return connection.ExecutePython(ctx, host, script, input, 2<<20)
	}
	staged, err := connection.ExecutePython(ctx, host, stageScript, input, 8192)
	if err != nil {
		return nil, err
	}
	var ref struct {
		Path string `json:"path"`
		SHA  string `json:"sha256"`
	}
	if json.Unmarshal(staged, &ref) != nil || ref.SHA != digestBytes(input) {
		return nil, errors.New("tailnet request staging failed verification")
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		b, _ := json.Marshal(map[string]string{"path": ref.Path})
		_, _ = connection.ExecutePython(c, host, cleanupScript, b, 1024)
	}()
	wrapper := `import base64,contextlib,hashlib,io,json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]);s=p.lstat();uid=int(os.environ.get('SUDO_UID',os.getuid()))
if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_mode&0o077 or s.st_size>2*1024*1024:raise RuntimeError('unsafe request file')
b=p.read_bytes()
if hashlib.sha256(b).hexdigest()!=sys.argv[2]:raise RuntimeError('request changed')
sys.stdin=io.StringIO(b.decode());output=io.StringIO()
with contextlib.redirect_stdout(output):exec(` + strconv.Quote(script) + `)
raw=output.getvalue().encode()
if len(raw)>2*1024*1024:raise RuntimeError('response too large')
print('LAZYCLASH_TAILNET_RESULT='+base64.b64encode(raw).decode())
`
	cmd, err := connection.ManagedPrivilegedBatchCommand(ctx, host, wrapper, ref.Path, ref.SHA)
	if err != nil {
		return nil, err
	}
	var output, diagnostic limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	err = cmd.Run()
	if b, ok := privilegedResult(output.String()); ok {
		return b, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	message := strings.ToLower(diagnostic.String())
	if err == nil || (!strings.Contains(message, "a password is required") && !strings.Contains(message, "a terminal is required") && !strings.Contains(message, "no tty present")) {
		return nil, errors.New("privileged tailnet result is unconfirmed; inspect before retrying")
	}
	if foreground == nil {
		return nil, &AuthorizationRequiredError{Host: host}
	}
	cmd, err = connection.ManagedPrivilegedCommand(ctx, host, wrapper, ref.Path, ref.SHA)
	if err != nil {
		return nil, err
	}
	output.Reset()
	terminal := nativeOutput{capture: &output, sink: dynamicTerminalOutput{command: cmd}}
	cmd.Stdout = &terminal
	if err = foreground(cmd); err != nil {
		return nil, fmt.Errorf("privileged tailnet operation canceled or failed: %w", err)
	}
	if b, ok := privilegedResult(output.String()); ok {
		return b, nil
	}
	return nil, errors.New("privileged tailnet helper returned no verified result")
}
func privilegedResult(output string) ([]byte, bool) {
	for _, line := range strings.Split(output, "\n") {
		if at := strings.Index(line, "LAZYCLASH_TAILNET_RESULT="); at >= 0 {
			data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[at+len("LAZYCLASH_TAILNET_RESULT="):]))
			if err == nil {
				return data, true
			}
		}
	}
	return nil, false
}

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 3<<20 {
		return 0, errors.New("tailnet helper output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func digestBytes(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// Native SSH sudo prompts arrive on stdout because remote -tt combines its
// terminal streams. Forward prompts immediately, suppressing private protocol
// lines even when their marker arrives split across read chunks.
type nativeOutput struct {
	capture io.Writer
	sink    io.Writer
	pending []byte
	result  bool
}

func (w *nativeOutput) Write(data []byte) (int, error) {
	if _, err := w.capture.Write(data); err != nil {
		return 0, err
	}
	const marker = "LAZYCLASH_TAILNET_RESULT="
	var visible []byte
	for _, b := range data {
		if w.result {
			if b == '\n' {
				w.result = false
			}
			continue
		}
		w.pending = append(w.pending, b)
		for len(w.pending) > 0 && !strings.HasPrefix(marker, string(w.pending)) {
			visible = append(visible, w.pending[0])
			w.pending = w.pending[1:]
		}
		if string(w.pending) == marker {
			w.result = true
			w.pending = nil
		}
	}
	if len(visible) > 0 {
		if _, err := w.sink.Write(visible); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

type dynamicTerminalOutput struct{ command *exec.Cmd }

func (w dynamicTerminalOutput) Write(data []byte) (int, error) {
	sink := w.command.Stderr
	if sink == nil {
		sink = os.Stderr
	}
	return sink.Write(data)
}
