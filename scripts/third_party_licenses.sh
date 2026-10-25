#!/usr/bin/env bash
# Writes the licence (and NOTICE, where there is one) of every module compiled into the
# binary on any release platform, for the release archives. Usage: third_party_licenses.sh OUT
set -euo pipefail
out=${1:?usage: third_party_licenses.sh OUT}

modules=$(for os in linux darwin windows; do
  GOOS=$os go list -deps -f '{{with .Module}}{{.Path}}@{{.Version}}{{end}}' ./cmd/credenshare
done | grep -v '^github.com/CredenShare/credenshare-cli@' | sort -u)

: >"$out"
# The Go runtime and standard library are compiled into every binary too.
printf '==== the Go standard library and runtime (%s) ====\n\n' "$(go env GOVERSION)" >>"$out"
cat "$(go env GOROOT)/LICENSE" >>"$out"
printf '\n\n' >>"$out"
for module in $modules; do
  dir=$(go mod download -json "$module" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
  found=0
  for file in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
    [ -f "$file" ] || continue
    found=1
    printf '==== %s (%s) ====\n\n' "$module" "$(basename "$file")" >>"$out"
    cat "$file" >>"$out"
    printf '\n\n' >>"$out"
  done
  if [ "$found" = 0 ]; then
    echo "no licence file found for $module" >&2
    exit 1
  fi
done
echo "wrote the licences of $(echo "$modules" | wc -l | tr -d ' ') module(s) to $out"
