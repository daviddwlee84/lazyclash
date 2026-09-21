#!/bin/sh
set -eu
mkdir -p completions
go run ./cmd/lazyclash completion bash > completions/lazyclash.bash
go run ./cmd/lazyclash completion zsh > completions/lazyclash.zsh
test -s completions/lazyclash.bash
test -s completions/lazyclash.zsh
