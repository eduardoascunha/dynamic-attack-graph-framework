.PHONY: help run ingest down clean

# Load variables from .env
-include .env
export

# Set SCENARIO on the command line to switch test cases (default: scenario1)
SCENARIO ?= scenario1

help:
	@echo "Attack Graph Generation Pipeline"
	@echo "================================="
	@echo ""
	@echo "Commands:"
	@echo "  make run               Run full pipeline (without threat intel ingestion)"
	@echo "  make ingest            Run full pipeline WITH threat intel ingestion"
	@echo ""
	@echo "Scenarios:"
	@echo "  SCENARIO=<name>        Select test case (default: scenario1)"
	@echo "                         Example: make run SCENARIO=scenario2"
	@echo ""
	@echo "Cleanup:"
	@echo "  make down              Stop all services"
	@echo "  make clean             Remove all containers and volumes"

# Run pipeline without threat intelligence ingestion
run:
	@echo "Running pipeline without threat intelligence ingestion..."
	docker compose up --build

# Run pipeline WITH threat intelligence ingestion
ingest:
	@echo "Running pipeline with threat intelligence ingestion..."
	docker compose --profile ingest up --build

# Stop all services
down:
	docker compose down

# Remove all containers, volumes, and networks
clean:
	docker compose --profile ingest down -v --remove-orphans
