#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load environment variables
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Activate virtual environment
if [ -d "$PROJECT_DIR/.venv" ]; then
    source "$PROJECT_DIR/.venv/bin/activate"
fi

# Parse arguments
while getopts "p:" opt; do
  case $opt in
    p)
      export PORT=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

# Run with gunicorn
echo "Starting application with gunicorn on port ${PORT:-5555}..."
cd "$PROJECT_DIR"
exec gunicorn --bind 0.0.0.0:${PORT:-5555} --workers 4 --preload src.main:app
