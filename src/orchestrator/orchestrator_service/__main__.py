import argparse

from .utils.logger import Logger
from .controller.orchestrator import Orchestrator
from .handlers.mulval_executor import NoAttackPathsFoundError


def main():
    parser = argparse.ArgumentParser(description="Attack Graph Orchestrator")
    parser.add_argument(
        "--config",
        type=str,
        help="Path to the configuration file",
        default=".config/config.toml",
    )
    parser.add_argument(
        "--log-config",
        type=str,
        help="Path to the log configuration file",
        default=".config/logging.ini",
    )
    parser.add_argument(
        "--mapped-scenario",
        type=str,
        help="Path to the mapped scenario file",
        default="/output/scenario.P",
    )
    parser.add_argument(
        "--graph-dir",
        type=str,
        help="Directory for generated attack graphs",
        default="/gen_graph",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force graph regeneration even if no changes detected",
    )
    args = parser.parse_args()
    Logger.configure(config_file=args.log_config)

    try:
        orchestrator = Orchestrator(config_path=args.config)
        orchestrator.orchestrate(
            mapped_scenario=args.mapped_scenario,
            graph_output_dir=args.graph_dir,
            force_regenerate=args.force,
        )
    except NoAttackPathsFoundError:
        logger = Logger.get_logger()
        logger.info("No attack paths found.")
        raise SystemExit(1)

if __name__ == "__main__":
    main()