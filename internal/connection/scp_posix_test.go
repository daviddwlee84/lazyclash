package connection

import "testing"

func TestPrivateCopyPOSIXPath(t *testing.T) {
	good := "/Users/david/.cache/lazyclash/managed-transfers/mac-verge-0123/verge.dmg"
	if got, err := privateCopyPOSIXPath(good); err != nil || got != good {
		t.Fatalf("valid transfer path rejected: %v", err)
	}
	for _, bad := range []string{"relative/.cache/lazyclash/managed-transfers/x", "/tmp/x", "/Users/david/.cache/lazyclash/managed-transfers/../x", "/Users/david/.cache/lazyclash/managed-transfers/x;rm", "/Users/david/.cache/lazyclash/managed-transfers/x/", "/Users/$USER/.cache/lazyclash/managed-transfers/x", "~/.cache/lazyclash/managed-transfers/x"} {
		if _, err := privateCopyPOSIXPath(bad); err == nil {
			t.Fatalf("unsafe POSIX transfer path accepted: %s", bad)
		}
	}
}
