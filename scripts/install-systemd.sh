#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

echo "Systemd Installation"
echo "=============================================="
echo "Project directory: $PROJECT_DIR"
echo ""

# Load environment variables from .env
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
    echo "Environment variables loaded from .env"
else
    echo "Warning: .env file not found"
fi

PORT=${PORT:-5555}
echo "Using PORT: $PORT"

# Create systemd directory
echo "Setting up systemd units..."
mkdir -p "$SYSTEMD_USER_DIR"

if [ -d "$SCRIPT_DIR/systemd" ]; then
    for unit_file in "$SCRIPT_DIR/systemd"/*.service "$SCRIPT_DIR/systemd"/*.timer; do
        if [ ! -e "$unit_file" ]; then continue; fi
        filename=$(basename "$unit_file")
        echo "Installing $filename..."
        
        # Replace placeholders and install
        sed -e "s|{{PROJECT_ROOT}}|$PROJECT_DIR|g" \
            -e "s|{{PORT}}|$PORT|g" \
            "$unit_file" > "$SYSTEMD_USER_DIR/$filename"
    done
else
    echo "Error: scripts/systemd directory not found!"
    exit 1
fi

echo "Systemd unit files installed to $SYSTEMD_USER_DIR/"
echo ""

# Reload systemd daemon
if command -v systemctl &> /dev/null; then
    echo "Reloading systemd daemon..."
    systemctl --user daemon-reload

    # Enable linger for the user
    if command -v loginctl &> /dev/null; then
        echo "Enabling linger for user $USER..."
        loginctl enable-linger "$USER" || echo "Warning: Failed to enable linger"
    fi

    # Enable and start services/timers
    echo "Enabling units..."
    
    for unit_file in "$SCRIPT_DIR/systemd"/*.service "$SCRIPT_DIR/systemd"/*.timer; do
        if [ ! -e "$unit_file" ]; then continue; fi
        filename=$(basename "$unit_file")
        
        systemctl --user enable "$filename"
        echo "Enabled $filename"
        
        # If it's a timer, start it
        if [[ "$filename" == *.timer ]]; then
             systemctl --user start "$filename"
             echo "Started timer $filename"
        fi
    done
    
    echo ""
    echo "Installation completed!"
    echo "To start the main service run: systemctl --user start drop5.service"
else
    echo "systemctl not found. Service files created but not loaded."
fi
