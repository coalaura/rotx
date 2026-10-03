#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=build-common.sh
source "$SCRIPT_DIR/build-common.sh"

usage() {
    cat <<'USAGE'
usage: tools/tor/build.sh <target>

targets:
  linux/amd64
  linux/arm64
  windows/amd64
  windows/arm64
  linux
  windows
  all

environment:
  JOBS=N               parallel make jobs
  TOR_CACHE_DIR=PATH   source tarball cache
  TOR_WORK_ROOT=PATH   temporary build root (default: /tmp)
  KEEP_WORK=1          retain temporary build trees after successful builds
  TOR_ENABLE_POW=1     enable Tor onion-service PoW support (GPL build mode)

The host only needs ordinary Unix CLI tools plus the exact Zig version pinned
in tools/tor/versions.sh. No GCC, MinGW, CMake, or system development libraries
are used.
USAGE
}

main() {
    if [[ $# -ne 1 ]]; then
        usage >&2
        exit 2
    fi

    check_tools
    download_sources

    case "$1" in
        linux/amd64|linux/arm64|windows/amd64|windows/arm64)
            build_target "$1"
            ;;
        linux)
            build_target linux/amd64
            build_target linux/arm64
            ;;
        windows)
            build_target windows/amd64
            build_target windows/arm64
            ;;
        all)
            build_target linux/amd64
            build_target linux/arm64
            build_target windows/amd64
            build_target windows/arm64
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"
