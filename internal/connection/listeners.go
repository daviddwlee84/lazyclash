package connection

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var pidPattern = regexp.MustCompile(`pid=([0-9]+)[,)]`)

func coreProcess(line string) (pid, command string, ok bool) {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", false
	}
	if _, err := strconv.Atoi(fields[0]); err == nil {
		pid = fields[0]
		line = strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		fields = strings.Fields(line)
	}
	if len(fields) == 0 {
		return "", "", false
	}
	binary := fields[0]
	if index := strings.LastIndex(binary, "/"); index >= 0 {
		binary = binary[index+1:]
	}
	binary = strings.Trim(strings.ToLower(binary), "'\"")
	ok = binary == "mihomo" || strings.HasPrefix(binary, "mihomo-") || binary == "verge-mihomo" || binary == "clash" || binary == "clash-meta" || binary == "clash-premium"
	return pid, line, ok
}

func corePIDs(ps string) []string {
	var pids []string
	for _, line := range strings.Split(ps, "\n") {
		pid, _, ok := coreProcess(line)
		if ok && pid != "" {
			pids = append(pids, pid)
			if len(pids) >= 32 {
				break
			}
		}
	}
	return pids
}

func processListeners(ctx context.Context, sshHost, ps string) []string {
	pids := corePIDs(ps)
	if len(pids) == 0 {
		return nil
	}
	var output []byte
	if sshHost == "" {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, _ = commandContext(ctx, "lsof", "-nP", "-a", "-p", strings.Join(pids, ","), "-iTCP", "-sTCP:LISTEN", "-Fpn").Output()
		if len(output) == 0 {
			output, _ = commandContext(ctx, "ss", "-lntp").Output()
		}
	} else {
		// PIDs were parsed as integers; they cannot add shell syntax. No sudo is
		// used, so only listener metadata visible to the SSH account is inspected.
		script := "if command -v lsof >/dev/null 2>&1; then lsof -nP -a -p " + strings.Join(pids, ",") + " -iTCP -sTCP:LISTEN -Fpn 2>/dev/null; elif command -v ss >/dev/null 2>&1; then ss -lntp 2>/dev/null; fi; true"
		output, _ = remoteCommand(ctx, sshHost, script, 1<<20)
	}
	return parseListeners(string(output), pids)
}

func parseListeners(output string, pids []string) []string {
	allowed := map[string]bool{}
	for _, pid := range pids {
		allowed[pid] = true
	}
	seen := map[string]bool{}
	var endpoints []string
	owned := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 2 {
			continue
		}
		address := ""
		switch line[0] {
		case 'p':
			owned = allowed[line[1:]]
		case 'n':
			if owned {
				address = line[1:]
			}
		default:
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[0] != "LISTEN" {
				continue
			}
			for _, match := range pidPattern.FindAllStringSubmatch(line, -1) {
				if allowed[match[1]] {
					address = fields[3]
					break
				}
			}
		}
		if address == "" {
			continue
		}
		endpoint, err := normalizeController(address, "http")
		if err != nil || seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		endpoints = append(endpoints, endpoint)
		if len(endpoints) >= 32 {
			break
		}
	}
	return endpoints
}
