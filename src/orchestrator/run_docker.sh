#!/usr/bin/env bash
# Run the orchestrator container with any extra arguments appended.
# Usage: SCENARIO=<name> ./run_docker.sh [extra args...]
# Example: SCENARIO=scenario1 ./run_docker.sh --force
#          SCENARIO=scenario1 ./run_docker.sh --graph-dir /custom/path --force
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

docker compose run --rm --build orchestrator_app \
    poetry run python -m orchestrator_service \
    --config .config/config.toml \
    --log-config .config/logging.ini \
    --mapped-scenario /output/scenario.P \
    --graph-dir /gen_graph \
    "$@"