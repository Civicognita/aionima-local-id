#!/usr/bin/env bash
# PAM authentication helper for agi-local-id.
#
# Verifies a system user's password via the `su` command (which consults
# PAM internally). Reads username from argv[1] and password from stdin.
# Exits 0 on successful authentication, non-zero on failure.
#
# Installation (host admin task):
#   sudo install -m 4755 -o root -g root \
#     /opt/agi-local-id/helpers/pam_auth.sh \
#     /opt/agi-local-id/helpers/pam_auth.sh
#
# The setuid bit is required so PAM can read /etc/shadow. Script is
# intentionally tiny + read-only so a security review can audit the
# whole attack surface in one sitting.
#
# **Caveats:**
# - The container version of Local-ID cannot use this directly; PAM
#   setup needs a sidecar or host-shell-out. See docs for container
#   deployment — PAM is currently only viable for bare-metal installs.
# - `su -c true $USER` is used instead of invoking a PAM library
#   directly because it works without a native Node addon and matches
#   the common Linux pattern. `expect`-less: we pipe the password in.

set -u

USERNAME="${1:-}"
if [[ -z "$USERNAME" ]]; then
  echo "usage: $0 <username> <<< password" >&2
  exit 64
fi

# Whitelist: only allow username strings that match standard POSIX user
# naming — belt + suspenders against argument injection into `su`.
if [[ ! "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "invalid username shape" >&2
  exit 64
fi

# Read password from stdin (never argv — argv shows up in `ps`).
IFS= read -r PASSWORD

# Pipe password into `su`. `su -c true` runs a no-op command as the
# target user — PAM challenges for a password, stdin provides it.
# Exit 0 = authenticated; non-zero = rejected or user doesn't exist.
printf '%s\n' "$PASSWORD" | su "$USERNAME" -c 'exit 0' 2>/dev/null
exit $?
