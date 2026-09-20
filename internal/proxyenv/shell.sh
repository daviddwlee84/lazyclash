# lazyclash shell integration. Generated text only; no network at shell startup.
__lazyclash_proxy_command() { command @BINARY@ "$@"; }

__lazyclash_proxy_snapshot() {
  [ "${__lazyclash_proxy_saved:-0}" = 1 ] && return 0
  local lc_key
  for lc_key in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY LAZYCLASH_PROXY_SESSION; do
    eval "__lazyclash_proxy_set_${lc_key}=\${${lc_key}+x}"
    eval "__lazyclash_proxy_old_${lc_key}=\${${lc_key}-}"
  done
  __lazyclash_proxy_saved=1
}

__lazyclash_proxy_restore() {
  [ "${__lazyclash_proxy_saved:-0}" = 1 ] || return 0
  local lc_key lc_set lc_value
  for lc_key in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY LAZYCLASH_PROXY_SESSION; do
    eval "lc_set=\${__lazyclash_proxy_set_${lc_key}-}"
    if [ "$lc_set" = x ]; then
      eval "lc_value=\${__lazyclash_proxy_old_${lc_key}-}"
      export "$lc_key=$lc_value"
    else
      unset "$lc_key"
    fi
    unset "__lazyclash_proxy_set_${lc_key}" "__lazyclash_proxy_old_${lc_key}"
  done
  __lazyclash_proxy_saved=0
}

__lazyclash_proxy_release_own() {
  if [ "${__lazyclash_proxy_owner:-}" = "$$" ] && [ -n "${__lazyclash_proxy_lease:-}" ]; then
    __lazyclash_proxy_command proxy tunnel stop "$__lazyclash_proxy_lease" >/dev/null || return
    __lazyclash_proxy_lease=''
  fi
}

lazyclash-proxy-on() {
  local lc_id lc_script lc_previous
  lc_id="$(__lazyclash_proxy_command proxy tunnel new-id)" || return
  # Authentication runs before stdout is captured for the env handoff.
  __lazyclash_proxy_command proxy tunnel start --lease "$lc_id" --shell-pid "$$" "$@" || return
  if ! lc_script="$(__lazyclash_proxy_command proxy env --session "$lc_id" --shell @SHELL@)"; then
    __lazyclash_proxy_command proxy tunnel stop "$lc_id" >/dev/null
    return 1
  fi
  lc_previous="${__lazyclash_proxy_lease:-}"
  __lazyclash_proxy_snapshot
  if ! eval "$lc_script"; then
    __lazyclash_proxy_restore
    __lazyclash_proxy_command proxy tunnel stop "$lc_id" >/dev/null
    return 1
  fi
  export LAZYCLASH_PROXY_SESSION="$lc_id"
  __lazyclash_proxy_lease="$lc_id"
  __lazyclash_proxy_owner="$$"
  if [ -n "$lc_previous" ] && [ "$lc_previous" != "$lc_id" ]; then
    __lazyclash_proxy_command proxy tunnel stop "$lc_previous" >/dev/null || printf '%s\n' 'Previous proxy session could not be closed; use lazyclash proxy tunnel cleanup.' >&2
  fi
}

lazyclash-proxy-off() {
  __lazyclash_proxy_restore
  __lazyclash_proxy_release_own
}
lazyclash-proxy-status() { __lazyclash_proxy_command proxy status "$@"; }
lazyclash-proxy-test() { __lazyclash_proxy_command proxy test "$@"; }
lazyclash-proxy-refresh() {
  if [ -n "${LAZYCLASH_PROXY_SESSION:-}" ]; then
    __lazyclash_proxy_command proxy tunnel status "$LAZYCLASH_PROXY_SESSION"
  else
    __lazyclash_proxy_command proxy status "$@"
  fi
}
lazyclash-withproxy() (
  [ "$#" -gt 0 ] || { printf '%s\n' 'withproxy requires a command' >&2; return 2; }
  lc_script="$(__lazyclash_proxy_command proxy env --shell @SHELL@)" || return
  eval "$lc_script" || return
  "$@"
)

# Generic names are opt-in replacements, or installed only if unclaimed.
if [ @REPLACE@ = 1 ] || ! command -v proxy-on >/dev/null 2>&1; then proxy-on() { lazyclash-proxy-on "$@"; }; fi
if [ @REPLACE@ = 1 ] || ! command -v proxy-off >/dev/null 2>&1; then proxy-off() { lazyclash-proxy-off "$@"; }; fi
if [ @REPLACE@ = 1 ] || ! command -v proxy-status >/dev/null 2>&1; then proxy-status() { lazyclash-proxy-status "$@"; }; fi
if [ @REPLACE@ = 1 ] || ! command -v proxy-test >/dev/null 2>&1; then proxy-test() { lazyclash-proxy-test "$@"; }; fi
if [ @REPLACE@ = 1 ] || ! command -v proxy-refresh >/dev/null 2>&1; then proxy-refresh() { lazyclash-proxy-refresh "$@"; }; fi
if [ @REPLACE@ = 1 ] || ! command -v withproxy >/dev/null 2>&1; then withproxy() { lazyclash-withproxy "$@"; }; fi

# Hook once, preserving the caller's existing handlers. No hooks spawn traffic.
if [ "${__lazyclash_proxy_hook:-}" != "$$" ]; then
  if [ -n "${ZSH_VERSION:-}" ]; then
    autoload -Uz add-zsh-hook
    __lazyclash_proxy_zshexit() { __lazyclash_proxy_release_own >/dev/null 2>&1; return 0; }
    add-zsh-hook zshexit __lazyclash_proxy_zshexit
  elif [ -n "${BASH_VERSION:-}" ]; then
    __lazyclash_proxy_capture_exit() { __lazyclash_proxy_previous_exit="$1"; }
    __lazyclash_proxy_trap="$(trap -p EXIT)"
    __lazyclash_proxy_previous_exit=''
    if [ -n "$__lazyclash_proxy_trap" ]; then
      eval "__lazyclash_proxy_capture_exit ${__lazyclash_proxy_trap#trap -- }"
    fi
    __lazyclash_proxy_return() { return "$1"; }
    __lazyclash_proxy_bash_exit() {
      local lc_rc=$?
      __lazyclash_proxy_release_own >/dev/null 2>&1 || :
      if [ -n "${__lazyclash_proxy_previous_exit:-}" ]; then
        if __lazyclash_proxy_return "$lc_rc"; then eval "$__lazyclash_proxy_previous_exit"; else eval "$__lazyclash_proxy_previous_exit"; fi
      fi
      return "$lc_rc"
    }
    trap '__lazyclash_proxy_bash_exit' EXIT
  fi
  __lazyclash_proxy_hook="$$"
fi
