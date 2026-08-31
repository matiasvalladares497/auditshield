#!/usr/bin/env bash
set -e

echo "=== AuditShield Backend Build ==="
pip install --upgrade pip
pip install -r requirements.txt
echo "=== Build Complete ==="
