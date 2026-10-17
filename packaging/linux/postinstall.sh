#!/bin/sh
# Start the agent at every user's login, and register the polinetwork-sign:// handler.
set -e
if command -v systemctl >/dev/null 2>&1; then
	systemctl --global enable polinetwork-sign-agent.service >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
	update-desktop-database -q /usr/share/applications || true
fi
