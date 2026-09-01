#!/usr/bin/env bash
set -e
export IP_SENTINEL_SCAN_MODE=real
export IP_SENTINEL_INTERFACE=${IP_SENTINEL_INTERFACE:-eth0}
export IP_SENTINEL_CIDR=${IP_SENTINEL_CIDR:-192.168.2.0/24}
exec sudo -E .venv/bin/python app.py
