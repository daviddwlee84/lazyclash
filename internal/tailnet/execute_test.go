package tailnet

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNativePrivilegePromptIsVisibleWithoutLeakingResult(t *testing.T) {
	var captured, visible bytes.Buffer
	w := nativeOutput{capture: &captured, sink: &visible}
	secretResult := base64.StdEncoding.EncodeToString([]byte(`{"ack_token":"private-token"}`))
	parts := []string{"[sudo] password for fixture-user: ", "\r\nLAZYCLASH_TAIL", "NET_RESULT=", secretResult[:7], secretResult[7:] + "\r\n", "Connection closed.\r\n"}
	for i, p := range parts {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
		if i == 0 && !strings.Contains(visible.String(), "password for fixture-user: ") {
			t.Fatal("sudo prompt was buffered until newline")
		}
	}
	if strings.Contains(visible.String(), secretResult) || strings.Contains(visible.String(), "RESULT") {
		t.Fatalf("private protocol streamed to terminal: %q", visible.String())
	}
	if _, ok := privilegedResult(captured.String()); !ok {
		t.Fatal("did not capture private response")
	}
	if !strings.Contains(visible.String(), "Connection closed.") {
		t.Fatal("post-result terminal diagnostic hidden")
	}
}
