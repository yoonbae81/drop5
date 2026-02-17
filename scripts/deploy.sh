#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="drop5"

echo "Starting deployment for $SERVICE_NAME..."

# 1. Pull latest code
echo "Pulling latest changes from git..."
git pull origin main

# 2. Update dependencies
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    echo "Updating dependencies..."
    "$PROJECT_DIR/.venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
fi

# 3. Restart services
echo "Restarting service..."
if command -v systemctl &> /dev/null; then
    systemctl --user restart "$SERVICE_NAME.service"
    echo "Service $SERVICE_NAME restarted."
else
    echo "Warning: systemctl not found, could not restart service."
fi

echo "Deployment completed successfully!"
