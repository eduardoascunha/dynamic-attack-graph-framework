import argparse

from .utils.logger import Logger
from .controller.threat_intelligence_controller import ThreatIntelligenceController


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Ingestion")
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
    args = parser.parse_args()
    Logger.configure(config_file=args.log_config)
    ThreatIntelligenceController(config_path=args.config).sync_vulnerability_data()


if __name__ == "__main__":
    main()
