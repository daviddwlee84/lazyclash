package cli

import (
	"runtime/debug"
	"strings"
)

func versionFromBuild() string {
	info, ok := debug.ReadBuildInfo()
	return resolveVersion(Version, info, ok)
}

func resolveVersion(injected string, info *debug.BuildInfo, ok bool) string {
	if version := strings.TrimSpace(injected); version != "" && version != "dev" && version != "(devel)" {
		return version
	}
	if ok && info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
