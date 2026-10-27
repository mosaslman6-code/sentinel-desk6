#!/bin/sh
cd "$(dirname "$0")" || exit 1
if [ -f notification-config.sh ]; then . ./notification-config.sh; fi
exec python3 server.py
