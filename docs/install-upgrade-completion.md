# Installation, upgrades and shell completion

## Source release channel

```sh
go install github.com/daviddwlee84/lazyclash/cmd/lazyclash@latest
lazyclash --version
lazyclash upgrade --check --json
lazyclash upgrade
```

Go 1.25+ is required. The executable package is `/cmd/lazyclash`, not the
repository root. GOBIN controls install location; otherwise Go uses GOPATH/bin.
`@latest` selects a published version, `@v0.1.11` pins one, and `@main` opts
into development. Prebuilt archives cover macOS/Linux amd64/arm64 and include checksums and Bash/Zsh completions. Package-manager publication is maintained separately.

The updater resolves the current executable, identifies build provenance and
package ownership, fetches a stable release, builds a fixed-tag candidate,
verifies it and atomically replaces the same resolved path. Relocated Go
release binaries and retained symlinks are supported. Destination changes,
concurrent updates and failed candidate validation preserve the original.

Provenance is evidence, not perfect installer detection. Homebrew-owned copies
delegate to the installed formula's `brew upgrade`. The keg receipt and owning
Cellar determine the target; a different Homebrew on PATH is rejected.
`upgrade --check` only previews this command and does not need GitHub metadata.
After success, the updater verifies the stable `opt` executable and reports its
actual version, including when Homebrew leaves a pinned/current formula unchanged.
Nix/mise copies retain their manager's guidance; unknown builds are not overwritten.
Unmanaged development builds require explicit `--force`, which does not bypass ownership
checks or force a Homebrew reinstall. The updater does not edit the checkout, use sudo, bootstrap Go or check
at startup. Go retains the user's GOTOOLCHAIN policy.

`--read-only` protects core operations, not local registrations or executable
updates. Use `upgrade --check` for a no-write update inspection.

## Four completion stages

1. **Generate:** `lazyclash completion zsh` emits a script.
2. **Install:** `lazyclash completion install zsh` writes a user completion file.
3. **Activate:** zsh must have the directory in fpath before compinit.
4. **Query:** the bridge asks the currently invoked binary for candidates.

```sh
lazyclash completion install zsh
lazyclash completion status zsh --json
# Or use an existing completion directory:
lazyclash completion install zsh --dir ~/.zfunc
```

The default directory is XDG_DATA_HOME/lazyclash/completions/zsh, falling back
to ~/.local/share. Installation prints the appropriate fpath/compinit snippet.
With Oh My Zsh or another framework, place fpath before the framework's
initialization instead of repeatedly calling compinit. The command does not
edit shell rc files or system/package-manager directories.

Status checks the installed file; a child process cannot prove that the parent
interactive shell activated it. Foreign regular files require explicit
`--force`; symlink destinations are not followed.

Cobra 1.10.2's zsh bridge queries the current binary through `__complete`, so
new commands/flags/candidates generally work after replacing that binary.
Regenerate if the bridge itself changes. The existing Bash generator is a
different, static mechanism: regenerate it after command-tree changes.

Candidate lookup reads local saved target/config IDs, saved SSH aliases and
static enums. It never connects to a controller/SSH host or resolves a secret.
Broken settings omit dynamic values while static completion remains usable.
Runtime proxy/node names are inspected through CLI/TUI, not fetched on Tab.

## Maintainer's chezmoi integration

The separate dotfiles repository registers lazyclash in its Go tool manifest
for macOS and Linux, under the existing optional runtime gate. Install is
create-only; updates remain explicit through `just upgrade-go` or lazyclash's
own updater. Existing Linux-only Go tools retain their platform restrictions.

The dotfiles completion generator produces both zsh and bash scripts. Its zsh
directory, ~/.zfunc, is already placed before Oh My Zsh initializes completion.
This integration is optional; other users only need the product commands above.

## Release checklist

Record user-visible changes under Unreleased, run tests/race/vet and actual
PTY checks, update the version references, create an immutable tag and GitHub
release, and verify fixed-tag/latest installs and installed version reporting.
Use the same release number in CHANGELOG, docs and install manifests.

The embedded operating skill ships with the binary. The contributor skill is
maintained in awesome-lazy-tools and distributed through agent-skills' owned
collection, then refreshed in this project; ordinary users do not run that
development workflow.

## Archive upgrade channel

Official archives carry a release stamp separate from the displayed version. The updater verifies the exact platform archive against `checksums.txt`, inspects the candidate package/module/platform and release stamp, then runs a bounded version check before replacing the same resolved executable. Failed or missing downloads/checksums never fall back to a source build. Source-installed copies continue to build exact stable tags with Go; Homebrew-owned copies delegate to their manager, whose failure never triggers direct replacement.
