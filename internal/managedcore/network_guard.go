package managedcore

import (
	_ "embed"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
)

//go:embed network_guard.py
var networkGuardScript string

// The detached worker contains only this binary's fixed code. It lives in a
// protected directory; a privileged worker never executes a user-owned script.
func networkGuardPrelude(script string) string {
	definitions, _, ok := strings.Cut(script, "\n# MANAGED_ENTRYPOINT\n")
	if !ok {
		panic("managed helper is missing its entrypoint marker")
	}
	proxy := "proxy_api={'__name__':'lazyclash_system_proxy'}\nexec(" + strconv.Quote(networkcheck.SystemProxyScript) + ",proxy_api)\n"
	worker := proxy + definitions + "\n" + networkGuardScript + "\nnetwork_guard_worker(sys.argv[1])\n"
	return proxy + "GUARD_WORKER_SOURCE=" + strconv.Quote(worker) + "\n" + networkGuardScript + "\n"
}
