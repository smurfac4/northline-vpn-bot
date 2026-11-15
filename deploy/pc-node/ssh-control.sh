#!/bin/sh
set -eu
printf '%s\n' "$SSH_ORIGINAL_COMMAND" | /usr/bin/python3 /app/node_control.py
