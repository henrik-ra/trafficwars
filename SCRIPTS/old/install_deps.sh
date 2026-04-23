#!/usr/bin/env bash
set -euo pipefail

cd /root/LOAD_BALANCER_APP

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Installing pm2 globally..."
npm install -g pm2

echo "Starting app with pm2..."
pm2 start ecosystem.config.js
pm2 save

echo "Done."
