package connection

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// This opt-in integration check sends synthetic data only. The inert helper
// parses JSON and hashes memory; transport creates private temporary RPC files.
// Application state and proxy configuration remain unchanged.
func TestPowerShellLivePayloadIntegrity(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_PAYLOAD_LIVE")
	if host == "" {
		t.Skip("set an explicit Windows SSH alias for inert payload verification")
	}
	script := `param([string]$RequestJson);$r=$RequestJson|ConvertFrom-Json;$b=[Text.Encoding]::UTF8.GetBytes($r.payload);$h=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant();[Console]::Out.WriteLine((ConvertTo-Json -Compress @{length=$b.Length;sha256=$digest}))}finally{$h.Dispose()}`
	sizes := []int{32 << 10, 128 << 10, 1 << 20}
	if os.Getenv("LAZYCLASH_WINDOWS_PAYLOAD_LARGE") == "1" {
		sizes = append(sizes, 70<<20)
	}
	allSmallPassed := true
	for _, size := range sizes {
		if size > 1<<20 && !allSmallPassed {
			t.Log("large payload skipped because a small payload failed")
			break
		}
		ok := t.Run(fmt.Sprintf("bytes_%d", size), func(t *testing.T) {
			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			for i := range payload {
				payload[i] = alphabet[payload[i]&63]
			}
			want := sha256.Sum256(payload)
			input, err := json.Marshal(map[string]string{"payload": string(payload)})
			if err != nil {
				t.Fatal(err)
			}
			budget := 15 * time.Second
			if size > 1<<20 {
				budget = 90 * time.Second
				if raw := os.Getenv("LAZYCLASH_WINDOWS_PAYLOAD_TIMEOUT"); raw != "" {
					selected, err := time.ParseDuration(raw)
					if err != nil || selected <= 0 || selected > 3*time.Minute {
						t.Fatal("large payload timeout must be positive and at most3m")
					}
					budget = selected
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			started := time.Now()
			out, err := ExecutePowerShell(ctx, host, script, input, 1024)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("%d-byte inert payload after %s: %v", size, elapsed.Round(time.Millisecond), err)
			}
			var got struct {
				Length int    `json:"length"`
				SHA256 string `json:"sha256"`
			}
			if json.Unmarshal(out, &got) != nil || got.Length != size || got.SHA256 != hex.EncodeToString(want[:]) {
				t.Fatalf("payload integrity mismatch: size=%d returned_length=%d", size, got.Length)
			}
			t.Logf("verified %d bytes and SHA-256 in %s", size, elapsed.Round(time.Millisecond))
		})
		if !ok {
			allSmallPassed = false
		}
	}
}

func TestPowerShellLiveOutputAndCancellation(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_PAYLOAD_LIVE")
	if host == "" {
		t.Skip("set an explicit Windows SSH alias for inert bridge verification")
	}
	t.Run("output_128KiB", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := ExecutePowerShell(ctx, host, `param([string]$RequestJson);[Console]::Out.Write(('Z'*131072))`, []byte(`{}`), 132<<10)
		if err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256([]byte(strings.Repeat("Z", 128<<10)))
		if len(out) != 128<<10 || sha256.Sum256(out) != want {
			t.Fatalf("output integrity mismatch: returned_length=%d", len(out))
		}
		t.Log("verified 128KiB output and SHA-256")
	})
	t.Run("bounded_cancel", func(t *testing.T) {
		// Cancel while establishing transport and bound local SSH cleanup. This
		// proves local termination only, not remote reader termination.
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := ExecutePowerShell(ctx, host, `param([string]$RequestJson);[Console]::Out.WriteLine('{}')`, []byte(`{}`), 1024)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline not preserved: %v", err)
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("SSH cancellation exceeded bound: %s", elapsed)
		}
		t.Log("local transport cancellation returned within5s; no long-running remote helper was requested")
	})
}
