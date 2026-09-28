"""Entry point for the Environment Correlation Layer."""

import argparse

from .utils.logger import Logger
from .controller.enviroment_correlation_controller import EnviromentCorrelationController


def main() -> str:
    """Run the environment correlation process."""
    parser = argparse.ArgumentParser(description="Environment Correlation Layer")
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
        "--work-dir",
        type=str,
        help="Working directory containing mapping file and for scenario output",
        default="/app/enviroment"
    )
    parser.add_argument(
        "--registry-dir",
        type=str,
        help="Registry directory for archiving old scenario files",
        default="/app/enviroment/registry"
    )
    parser.add_argument(
        "--stride-file",
        type=str,
        help="Path to a STRIDE definition JSON file for optional threat model mapping",
        default=None,
    )
    args = parser.parse_args()
    Logger.configure(config_file=args.log_config)

    controller = EnviromentCorrelationController(config_path=args.config)

    mapped_scenario = controller.correlate_enviroment_with_threat_data(
        work_dir=args.work_dir,
        registry_dir=args.registry_dir,
        stride_file=args.stride_file,
    )

    return mapped_scenario


if __name__ == "__main__":
    main()
