#!/usr/bin/env bash
# Run the post-processing container with any extra arguments appended.
# Usage: SCENARIO=<name> ./run_docker.sh [extra args...]
# Example: SCENARIO=scenario1 ./run_docker.sh
#          SCENARIO=scenario1 ./run_docker.sh --graph-dir /custom/path
#          SCENARIO=scenario1 ./run_docker.sh --no-caption
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

docker compose run --rm --build post_processing_app \
    poetry run python -m post_processing_layer \
    --config .config/config.toml \
    --log-config .config/logging.ini \
    --graph-dir /gen_graph \
    --work-dir /post_processing \
    "$@"
