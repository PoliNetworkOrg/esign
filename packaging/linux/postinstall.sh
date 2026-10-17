#!/bin/sh
# Start the agent at every user's login, register the polinetwork-esign:// handler, and (re)start the agent for the
# users logged in now, so that neither a new login nor a command is needed. Runs after installs and upgrades.
set -e
if command -v systemctl >/dev/null 2>&1; then
	systemctl --global enable polinetwork-esign.service >/dev/null 2>&1 || true
	if [ -d /run/systemd/system ]; then
		# Debian's pcscd and Fedora's presets enable the socket already; Arch leaves it off.
		systemctl enable --now pcscd.socket >/dev/null 2>&1 || true
		for user in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}'); do
			# Versions up to v0.1.x ran as polinetwork-sign-agent.service, on the same port.
			systemctl --user --machine="$user@" stop polinetwork-sign-agent.service >/dev/null 2>&1 || true
			systemctl --user --machine="$user@" restart polinetwork-esign.service >/dev/null 2>&1 || true
		done
	fi
fi
if command -v update-desktop-database >/dev/null 2>&1; then
	update-desktop-database -q /usr/share/applications || true
fi
