#!/usr/bin/env bash
# Run the environment correlation container with any extra arguments appended.
# Usage: SCENARIO=<name> ./run_docker.sh [extra args...]
# Example: SCENARIO=scenario1 ./run_docker.sh
#          SCENARIO=scenario1 ./run_docker.sh --work-dir /app/enviroment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

docker compose run --rm --build environment_correlation_app \
    poetry run python -m enviroment_correlation_layer \
    --config .config/config.toml \
    --log-config .config/logging.ini \
    --work-dir /app/enviroment \
    --registry-dir /app/enviroment/registry \
    --stride-file /app/enviroment/stride_definition.json \
    "$@"
