#!/usr/bin/env bash
# Version CI de `./x.sh fuzz` : même script que dans le conteneur, la nightly épinglée et
# cargo-fuzz étant installés directement sur le runner GitHub (job `fuzz` de ci.yml).
set -euo pipefail
export NETSIFT_FUZZ_HOST=1
exec bash "$(dirname "${BASH_SOURCE[0]}")/../ct/fuzz.sh" "$@"
