//go:build windows

package privatefs

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateACLRejectsOtherReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	set := func(sddl string) {
		t.Helper()
		sd, e := windows.SecurityDescriptorFromString(sddl)
		if e != nil {
			t.Fatal(e)
		}
		acl, _, e := sd.DACL()
		if e != nil {
			t.Fatal(e)
		}
		if e := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
			t.Fatal(e)
		}
	}
	set("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if !Private(path) {
		t.Fatal("private user/SYSTEM ACL rejected")
	}
	set("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;WD)")
	if Private(path) {
		t.Fatal("Everyone-readable state accepted")
	}
}
