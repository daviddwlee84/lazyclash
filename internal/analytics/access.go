package analytics

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const maxAccessLine = 64 << 10
const maxAccessPoll = 1 << 20

type accessCheckpoint struct {
	Identity   string `json:"identity"`
	Offset     int64  `json:"offset"`
	Anchor     string `json:"anchor,omitempty"`
	Generation int64  `json:"generation"`
	Skipping   bool   `json:"skipping,omitempty"`
}

type accessTail struct {
	source   SourceConfig
	zone     *time.Location
	file     *os.File
	position accessCheckpoint
	restored bool
	last     time.Time
}

func checkAccessPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("access log path must be absolute on the collector host")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("access log must be a regular readable file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("access log must be a regular readable file")
	}
	return nil
}

// Only stable inode/device identifiers are retained; file content never enters checkpoints.
func accessFileIdentity(info os.FileInfo) string {
	v := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if v.IsValid() && v.Kind() == reflect.Struct {
		d, i := v.FieldByName("Dev"), v.FieldByName("Ino")
		if d.IsValid() && i.IsValid() {
			return fmt.Sprint(d.Interface(), ":", i.Interface())
		}
	}
	return fmt.Sprintf("%s:%d", info.Name(), info.ModTime().UnixNano())
}

func accessAnchor(f *os.File, offset int64) string {
	if offset == 0 {
		return ""
	}
	start := max(int64(0), offset-64)
	b := make([]byte, offset-start)
	n, err := f.ReadAt(b, start)
	if err != nil && err != io.EOF {
		return "unreadable"
	}
	return stableSourceID(string(b[:n]))
}

func (a *accessTail) close() {
	if a.file != nil {
		_ = a.file.Close()
		a.file = nil
	}
}

func (a *accessTail) open() (gaps int64, err error) {
	info, err := os.Stat(a.source.Path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("access log is not a regular readable file")
	}
	f, err := os.Open(a.source.Path)
	if err != nil {
		return 0, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return 0, errors.New("access log is not a regular readable file")
	}
	identity := accessFileIdentity(info)
	if !a.restored {
		// Opt-in starts at EOF; existing historical text is never silently imported.
		a.position = accessCheckpoint{Identity: identity, Offset: info.Size()}
		a.position.Anchor = accessAnchor(f, a.position.Offset)
	} else if a.position.Identity != identity || info.Size() < a.position.Offset || (a.position.Anchor != "" && a.position.Anchor != accessAnchor(f, a.position.Offset)) {
		gaps = 1
		a.position = accessCheckpoint{Identity: identity, Generation: a.position.Generation + 1}
	}
	a.restored = true
	a.file = f
	return gaps, nil
}

func (a *accessTail) poll(ctx context.Context, now time.Time) (Batch, int64, int64, error) {
	batch := Batch{SourceID: a.source.ID, Kind: a.source.Kind, Scope: sourceScope(a.source), At: now}
	var gaps, dropped int64
	if a.file == nil {
		var err error
		gaps, err = a.open()
		if err != nil {
			return batch, gaps, dropped, err
		}
	}
	info, err := a.file.Stat()
	if err != nil {
		return batch, gaps, dropped, err
	}
	if info.Size() < a.position.Offset || (a.position.Anchor != "" && a.position.Anchor != accessAnchor(a.file, a.position.Offset)) {
		a.position.Offset = 0
		a.position.Anchor = ""
		a.position.Skipping = false
		a.position.Generation++
		gaps++
	}
	if _, err = a.file.Seek(a.position.Offset, io.SeekStart); err != nil {
		return batch, gaps, dropped, err
	}
	r := bufio.NewReaderSize(io.LimitReader(a.file, maxAccessPoll), maxAccessLine)
	read := int64(0)
	for read < maxAccessPoll && len(batch.Events) < 4000 {
		if err = ctx.Err(); err != nil {
			return batch, gaps, dropped, err
		}
		start := a.position.Offset
		line, readErr := r.ReadSlice('\n')
		read += int64(len(line))
		if readErr == bufio.ErrBufferFull {
			if !a.position.Skipping {
				dropped++
			}
			a.position.Skipping = true
			a.position.Offset += int64(len(line))
			continue
		}
		if readErr == io.EOF {
			// Keep an ordinary incomplete trailing line at its last complete offset.
			// Oversized lines can advance safely without retaining raw fragments.
			if a.position.Skipping {
				a.position.Offset += int64(len(line))
			}
			break
		}
		if readErr != nil {
			return batch, gaps, dropped, readErr
		}
		a.position.Offset += int64(len(line))
		if a.position.Skipping {
			a.position.Skipping = false
			continue
		}
		event, ok := parseAccessLine(string(line), a.zone)
		if !ok {
			dropped++
			continue
		}
		if event.At.After(now.Add(time.Minute)) {
			dropped++
			continue
		}
		event.ID = stableSourceID(a.source.ID, a.position.Identity, fmt.Sprint(a.position.Generation), fmt.Sprint(start), event.At.Format(time.RFC3339Nano))
		batch.Events = append(batch.Events, event)
	}
	// Drain the open inode before following a renamed replacement. This keeps
	// buffered old-file writes visible without rereading compressed rotations.
	current, statErr := os.Stat(a.source.Path)
	if statErr == nil && accessFileIdentity(current) != a.position.Identity && read < maxAccessPoll {
		if info.Size() > a.position.Offset {
			dropped++
		} // incomplete final line on old inode
		a.close()
		a.position = accessCheckpoint{Identity: accessFileIdentity(current), Generation: a.position.Generation + 1}
		a.restored = true
	}
	if a.file != nil {
		a.position.Anchor = accessAnchor(a.file, a.position.Offset)
	}
	value, _ := json.Marshal(a.position)
	batch.Checkpoint = &Checkpoint{Key: "access", Value: value, UpdatedAt: now}
	if gaps == 0 && !a.last.IsZero() && now.Sub(a.last) <= 3*sourceInterval(a.source) {
		batch.CoverageStart = a.last
	}
	a.last = now
	return batch, gaps, dropped, nil
}

var accessLinePattern = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?:from\s+)?(\S+)\s+accepted\s+(\S+)(.*)$`)
var accessRoutePattern = regexp.MustCompile(`\[([^\]]+)\]`)
var accessPrincipalPattern = regexp.MustCompile(`(?:^|\s)email:\s*(\S+)`)

func parseAccessLine(line string, zone *time.Location) (Event, bool) {
	m := accessLinePattern.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Event{}, false
	}
	if zone == nil {
		zone = time.UTC
	}
	at, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], zone)
	if err != nil {
		return Event{}, false
	}
	client := accessHost(m[2])
	if net.ParseIP(client) == nil {
		return Event{}, false
	}
	destination := accessHost(m[3])
	if destination == "" {
		return Event{}, false
	}
	route := ""
	if r := accessRoutePattern.FindStringSubmatch(m[4]); r != nil {
		route = r[1]
	}
	principal := ""
	if p := accessPrincipalPattern.FindStringSubmatch(m[4]); p != nil {
		principal = p[1]
	}
	return Event{At: at, ClientIP: client, Domain: strings.ToLower(strings.TrimSuffix(sourceString(destination), ".")), Route: sourceString(route), Principal: sourceString(principal), Count: 1}, true
}

func accessHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "tcp:"), "udp:")
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	if net.ParseIP(s) != nil {
		return s
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 {
		return s[:i]
	}
	return s
}
