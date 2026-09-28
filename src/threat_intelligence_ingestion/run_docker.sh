#!/usr/bin/env bash
# Run the threat intelligence ingestion container with any extra arguments appended.
# Usage: ./run_docker.sh [extra args...]
# Example: ./run_docker.sh
#          ./run_docker.sh --config .config/custom.toml
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

docker compose --profile ingest run --rm --build threat_intelligence_app \
    poetry run python -m threat_intelligence_connector \
    --config .config/config.toml \
    --log-config .config/logging.ini \
    "$@"
