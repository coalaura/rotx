#!/bin/bash

fail() {
	printf '%s\n' "$*" >&2
	exit 1
}

require_root() {
	if [ "${EUID}" -ne 0 ]; then
		command -v sudo >/dev/null || fail "Run this installer as root (sudo is not installed)."
		exec sudo -- bash "$@"
	fi
}

require_file() {
	if [ -L "$1" ] || [ ! -f "$1" ]; then
		fail "Missing or unsafe file: $1"
	fi
}

check_identity() {
	local passwd_entry group_entry username password user_id group_id description home shell group_name group_password primary_group members
	passwd_entry=$(getent passwd rotx || true)
	group_entry=$(getent group rotx || true)
	IFS=: read -r username password user_id group_id description home shell <<< "${passwd_entry}"
	IFS=: read -r group_name group_password primary_group members <<< "${group_entry}"

	if [ -z "${passwd_entry}" ] || [ -z "${group_entry}" ] || [ "${user_id}" = 0 ] || [ "${group_id}" = 0 ] || [ "${group_id}" != "${primary_group}" ]; then
		fail "The rotx service requires its own non-root user and primary group."
	fi

	case "${shell}" in
		/bin/nologin|/usr/bin/nologin|/sbin/nologin|/usr/sbin/nologin) ;;
		*) fail "Refusing to reuse a login account named rotx." ;;
	esac
}

render_service() {
	local root=$1 template=$2 escaped="" character line
	local index

	if [[ "${root}" == *[[:cntrl:]]* ]]; then
		fail "The deployment path must not contain control characters."
	fi

	# Quote unit values and escape systemd specifiers independently of shell syntax.
	for ((index = 0; index < ${#root}; index++)); do
		character=${root:index:1}
		case "${character}" in
			'\') escaped+='\\' ;;
			'"') escaped+='\"' ;;
			'%') escaped+='%%' ;;
			*) escaped+="${character}" ;;
		esac
	done

	printf '# rotx deployment: %s\n' "${root}"
	while IFS= read -r line || [ -n "${line}" ]; do
		# WorkingDirectory is a single literal path, not a shell-style quoted word list.
		if [[ "${line}" == WorkingDirectory=* ]]; then
			printf 'WorkingDirectory=%s/\n' "${root//%/%%}"
			continue
		fi

		while [[ "${line}" == *'/opt/rotx'* ]]; do
			printf '%s%s' "${line%%/opt/rotx*}" "${escaped}"
			line=${line#*/opt/rotx}
		done
		printf '%s\n' "${line}"
	done < "${template}"
}
