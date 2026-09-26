package connection

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

const privateCopyLimit = 256 << 20

// CopyPrivateFile copies one bounded private file using OpenSSH's default SFTP
// transport. The caller must first prepare the exact private remote directory
// and verify the received size/hash before using the payload. This function does
// not create remote directories, retry a transfer, or fall back to legacy SCP.
func CopyPrivateFile(ctx context.Context, host, localPath, remotePath string) error {
	return CopyPrivateFileOS(ctx, host, localPath, remotePath, "windows")
}

// CopyPrivateFileOS is CopyPrivateFile for an explicit destination path OS.
// POSIX destinations must be inside the caller-prepared private transfer root
// ~/.cache/lazyclash/managed-transfers of the SSH user.
func CopyPrivateFileOS(ctx context.Context, host, localPath, remotePath, pathOS string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateHost(host); err != nil {
		return err
	}
	destination, err := scpDestinationHost(host)
	if err != nil {
		return err
	}
	if invalidPrivateCopyPath(localPath) {
		return errors.New("private copy source path contains invalid characters")
	}
	localPath, err = filepath.Abs(localPath)
	if err != nil {
		return errors.New("private copy requires an absolute local file")
	}
	before, err := os.Lstat(localPath)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > privateCopyLimit {
		return errors.New("private copy requires a bounded regular file")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 {
		return errors.New("private copy source must be readable only by its owner")
	}
	if pathOS == "windows" {
		remotePath, err = privateCopyRemotePath(remotePath)
	} else {
		remotePath, err = privateCopyPOSIXPath(remotePath)
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	// OpenSSH before 9.0 defaulted to a remote shell-based protocol. Never
	// silently use it on an older installation, even when no -O was requested.
	if err = requireSFTPDefault(ctx); err != nil {
		return err
	}
	args, err := sshArgsContext(ctx, host)
	if err != nil {
		return err
	}
	args = append(args, "-q", "--", localPath, destination+":"+remotePath)
	cmd := commandContext(ctx, "scp", args...)
	// All values are individual argv entries. Paths with spaces/CJK are not
	// shell-quoted: the SFTP client receives their literal characters.
	var output, diagnostic limitedBuffer
	output.limit, diagnostic.limit = 8192, 8192
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	cmd.WaitDelay = 2 * time.Second
	configureHelperProcess(cmd)
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if output.Exceeded() || diagnostic.Exceeded() {
			return ErrHelperOutputLimit
		}
		if needsAuthentication(diagnostic.String()) {
			return &AuthRequiredError{Host: host}
		}
		if transport := classifySSHTransport(err, diagnostic.String()); transport != nil {
			return transport
		}
		return errors.New("private SFTP copy did not complete; inspect the prepared transfer before retrying")
	}
	if output.Exceeded() || diagnostic.Exceeded() {
		return ErrHelperOutputLimit
	}
	after, err := os.Lstat(localPath)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		return errors.New("private copy source changed during transfer; received payload must not be dispatched")
	}
	return nil
}

func invalidPrivateCopyPath(p string) bool {
	return p == "" || len(p) > 4096 || strings.IndexFunc(p, unicode.IsControl) >= 0
}

func privateCopyRemotePath(p string) (string, error) {
	// This operation currently stages only to caller-prepared Windows files.
	// Reject shell/glob syntax and ambiguous Windows aliases, not spaces/CJK.
	if invalidPrivateCopyPath(p) || !hostpath.IsAbs("windows", p) || strings.ContainsAny(p, "'\"`$;&|<>*?[]{}()!%^~") {
		return "", errors.New("private copy destination must be an unambiguous absolute Windows file path")
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) < 4 || p[1] != ':' || p[2] != '/' || strings.Contains(p[2:], ":") || strings.HasSuffix(p, "/") {
		return "", errors.New("private copy destination must be a drive-qualified Windows file path")
	}
	for _, part := range strings.Split(p[3:], "/") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", errors.New("private copy destination contains an ambiguous path component")
		}
	}
	return p, nil
}

func privateCopyPOSIXPath(p string) (string, error) {
	if invalidPrivateCopyPath(p) || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\'\"`$;&|<>*?[]{}()!%^~") || strings.HasSuffix(p, "/") {
		return "", errors.New("private copy destination must be an unambiguous absolute POSIX file path")
	}
	for _, part := range strings.Split(p[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("private copy destination contains an ambiguous path component")
		}
	}
	if !strings.Contains(p, "/.cache/lazyclash/managed-transfers/") {
		return "", errors.New("POSIX private copies are limited to the prepared managed transfer directory")
	}
	return p, nil
}

func scpDestinationHost(host string) (string, error) {
	user, server := "", host
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		user, server = host[:at+1], host[at+1:]
	}
	if strings.ContainsAny(server, "/\\") {
		return "", errors.New("private copy requires an SSH alias, not a remote path")
	}
	if strings.Contains(server, ":") {
		ip := strings.Trim(server, "[]")
		if net.ParseIP(ip) == nil {
			return "", errors.New("use a saved SSH alias for a host with a configured port")
		}
		return user + "[" + ip + "]", nil
	}
	return host, nil
}

var openSSHVersion = regexp.MustCompile(`(?m)^OpenSSH_(?:for_Windows_)?([0-9]+)\.[0-9]+`)

func requireSFTPDefault(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := commandContext(ctx, "ssh", "-V")
	var output limitedBuffer
	output.limit = 4096
	cmd.Stdout, cmd.Stderr = &output, &output
	cmd.WaitDelay = time.Second
	configureHelperProcess(cmd)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("private copy requires installed OpenSSH 9 or newer with default SFTP support")
	}
	match := openSSHVersion.FindStringSubmatch(output.String())
	if output.Exceeded() || len(match) != 2 {
		return errors.New("cannot verify OpenSSH default SFTP support; install OpenSSH 9 or newer")
	}
	major, err := strconv.Atoi(match[1])
	if err != nil || major < 9 {
		return errors.New("private copy requires OpenSSH 9 or newer; legacy SCP is disabled")
	}
	return nil
}
