#!/bin/bash
# Serve the GESH DC Fabric operations portal (static docs) over HTTP.
# Wired into launchd via ~/Library/LaunchAgents/com.geshlab.portal.plist
set -e

PORT="${PORTAL_PORT:-8099}"
DOCS_DIR="$(cd "$(dirname "$0")/../docs" && pwd)"

echo "Serving portal from ${DOCS_DIR} on port ${PORT}"
exec python3 -m http.server "${PORT}" --directory "${DOCS_DIR}" --bind 127.0.0.1
