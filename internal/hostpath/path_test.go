package hostpath

import "testing"

func TestWindowsPathsDoNotUseControllerPlatform(t *testing.T) {
	for _, p := range []string{`C:\Users\David User\設定\config.yaml`, "c:/Users/David/config.yaml", `\\nas\share\config.yaml`} {
		if !IsAbs("windows", p) {
			t.Errorf("absolute Windows path rejected: %s", p)
		}
	}
	for _, p := range []string{`C:config.yaml`, `/Users/David/config.yaml`, `\\?\C:\config.yaml`, `\\.\pipe\core`, `C:\file:secret`, `C:\*.yaml`} {
		if IsAbs("windows", p) {
			t.Errorf("unsafe/nonabsolute Windows path accepted: %s", p)
		}
	}
	root := `C:\Users\David\配置`
	joined := Join("windows", root, "profiles", "node.yaml")
	if joined != "C:/Users/David/配置/profiles/node.yaml" || Dir("windows", joined) != "C:/Users/David/配置/profiles" || Base("windows", joined) != "node.yaml" {
		t.Fatal(joined)
	}
	if !Within("windows", root, `c:\users\david\配置\profiles\node.yaml`) || Within("windows", root, `C:\Users\David\配置-other\node.yaml`) || Within("windows", root, `C:\Users\David\配置\..\secret`) || Within("windows", root, `D:\Users\David\配置\node.yaml`) {
		t.Fatal("containment changed")
	}
	for _, p := range []string{`C:\`, `\\nas\share\`, "/"} {
		os := "windows"
		if p == "/" {
			os = "linux"
		}
		if !IsRoot(os, p) {
			t.Error("root not identified", p)
		}
	}
	if Join("linux", "/home/user", "profiles", "node.yaml") != "/home/user/profiles/node.yaml" || !Within("linux", "/home/user", "/home/user/config.yaml") || Within("linux", "/home/user", "/home/user2/config.yaml") {
		t.Fatal("POSIX behavior changed")
	}
}
