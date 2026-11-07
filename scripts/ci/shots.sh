#!/usr/bin/env bash
# Version CI de `./x.sh shots` : même script que dans le conteneur, la toolchain épinglée
# étant installée directement sur le runner GitHub.
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/../ct/shots.sh" "${1:-all}"
