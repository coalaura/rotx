#!/bin/bash

set -euo pipefail

script=$(realpath -- "${BASH_SOURCE[0]}")
conf_dir=$(dirname -- "${script}")
path=$(dirname -- "${conf_dir}")
source "${conf_dir}/service.sh"
require_root "${script}" "$@"

unit_file=/etc/systemd/system/rotx.service
require_file "${unit_file}"
IFS= read -r header < "${unit_file}"
[ "${header}" = "# rotx deployment: ${path}" ] || fail "The installed service belongs to a different deployment."

systemctl stop rotx.service
systemctl disable rotx.service
rm -- "${unit_file}"
systemctl daemon-reload
systemctl reset-failed rotx.service 2>/dev/null || true

# Keep the identity reserved so retained private state never becomes another user's files.
printf 'Service removed. Application files, data, and the rotx service account were retained.\n'
