#!/bin/sh
# Undo postinstall.sh on removal only: dpkg passes "upgrade" and rpm 1 when another version replaces this one (rpm runs
# the old version's script after the new one's postinstall); pacman runs it only on removal.
set -e
case "${1:-}" in upgrade | failed-upgrade | 1) exit 0 ;; esac
if command -v systemctl >/dev/null 2>&1; then
	systemctl --global disable polinetwork-esign.service >/dev/null 2>&1 || true
	if [ -d /run/systemd/system ]; then
		for user in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}'); do
			systemctl --user --machine="$user@" stop polinetwork-esign.service >/dev/null 2>&1 || true
		done
	fi
fi
