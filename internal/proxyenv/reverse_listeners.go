package proxyenv

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Verification queries only the requested ports. Linux proc socket tables are
// readable without privilege; macOS lsof must expose the account's listeners.
// Missing tools, inaccessible tables and startup chatter fail closed.
func reverseListenerCommand(ports []int) string {
	var matches, decimal []string
	for _, port := range ports {
		matches = append(matches, fmt.Sprintf(`a[2]=="%04X"`, port))
		decimal = append(decimal, strconv.Itoa(port))
	}
	filter := strings.Join(matches, " || ")
	script := `case "$(uname -s)" in
Linux)
  [ -r /proc/net/tcp ] && [ -r /proc/net/tcp6 ] || exit 71
  printf 'linux\n'
  awk '$4 == "0A" {split($2,a,":"); if (` + filter + `) print "v4 " $2}' /proc/net/tcp || exit 71
  awk '$4 == "0A" {split($2,a,":"); if (` + filter + `) print "v6 " $2}' /proc/net/tcp6 || exit 71
  ;;
Darwin)
  printf 'darwin\n'
  /usr/sbin/lsof -nP -a -iTCP:` + strings.Join(decimal, ",") + ` -sTCP:LISTEN -Fn || exit 71
  ;;
*) exit 71 ;;
esac`
	return "exec /bin/sh -c " + Quote(script)
}

func verifyReverseListeners(ctx context.Context, s Session, ports []int, opts SessionOptions) error {
	if len(ports) == 0 {
		return errors.New("reverse SSH has no listeners to verify")
	}
	query, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := reverseCommand(query, s, reverseListenerCommand(ports), false)
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = 16384, 8192
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := runSessionCommand(cmd, opts); err != nil {
		return errors.New("cannot verify remote loopback listeners; Linux needs readable /proc/net/tcp{,6}, macOS needs lsof; reverse share closed")
	}
	if err := parseReverseListeners(stdout.String(), ports); err != nil {
		return err
	}
	return nil
}

func parseReverseListeners(raw string, ports []int) error {
	wanted := map[int]bool{}
	for _, port := range ports {
		wanted[port] = false
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 || (lines[0] != "linux" && lines[0] != "darwin") {
		return errors.New("remote listener inspection was incomplete; reverse share closed")
	}
	for _, line := range lines[1:] {
		var ip net.IP
		var port int
		if lines[0] == "linux" {
			kind, address, ok := strings.Cut(strings.TrimSpace(line), " ")
			host, rawPort, split := strings.Cut(address, ":")
			p, err := strconv.ParseInt(rawPort, 16, 32)
			data, decodeErr := hex.DecodeString(host)
			if !ok || !split || err != nil || decodeErr != nil || (kind != "v4" && kind != "v6") || (kind == "v4" && len(data) != 4) || (kind == "v6" && len(data) != 16) {
				return errors.New("remote listener inspection could not be parsed; reverse share closed")
			}
			// /proc renders native-endian 32-bit words on supported amd64/arm64
			// Linux hosts. Unknown representations are rejected, never assumed safe.
			for i := 0; i < len(data); i += 4 {
				data[i], data[i+3] = data[i+3], data[i]
				data[i+1], data[i+2] = data[i+2], data[i+1]
			}
			ip, port = net.IP(data), int(p)
		} else {
			// lsof includes process and descriptor fields even when only the
			// name field is explicitly requested with -Fn.
			if strings.HasPrefix(line, "p") || strings.HasPrefix(line, "f") {
				if _, err := strconv.Atoi(line[1:]); err != nil {
					return errors.New("remote listener inspection could not be parsed; reverse share closed")
				}
				continue
			}
			if !strings.HasPrefix(line, "n") {
				return errors.New("remote listener inspection could not be parsed; reverse share closed")
			}
			host, rawPort, err := net.SplitHostPort(strings.TrimPrefix(line, "n"))
			if err != nil {
				return errors.New("remote listener address is unverifiable; reverse share closed")
			}
			port, err = strconv.Atoi(rawPort)
			if err != nil {
				return errors.New("remote listener port is unverifiable; reverse share closed")
			}
			ip = net.ParseIP(host)
		}
		if _, expected := wanted[port]; !expected {
			return errors.New("remote listener inspection returned an unexpected port; reverse share closed")
		}
		if ip == nil || !ip.IsLoopback() {
			return errors.New("remote SSH listener is not loopback-only (GatewayPorts may force wildcard binding); reverse share closed")
		}
		wanted[port] = true
	}
	for _, found := range wanted {
		if !found {
			return errors.New("remote loopback listener could not be observed; reverse share closed")
		}
	}
	return nil
}
