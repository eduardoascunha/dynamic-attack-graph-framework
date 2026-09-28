"""
Entry point for the post-processing and dynamic risk analysis layer.
"""

import argparse

from .controller.post_processing_controller import PostProcessingController
from .utils.logger import Logger


def main():
    parser = argparse.ArgumentParser(
        description="Post-Processing and Dynamic Risk Analysis Layer"
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to the TOML configuration file",
        default=".config/config.toml",
    )
    parser.add_argument(
        "--log-config",
        type=str,
        help="Path to the logging INI configuration file",
        default=".config/logging.ini",
    )
    parser.add_argument(
        "--graph-dir",
        type=str,
        help="Directory containing MulVAL output (VERTICES.CSV, ARCS.CSV)",
        default="/gen_graph",
    )
    parser.add_argument(
        "--work-dir",
        type=str,
        help="Output directory for risk analysis JSON reports (delta compared against previous reports here)",
        default="/post_processing",
    )
    parser.add_argument(
        "--asset-cpe-mapping",
        type=str,
        help="Path to asset_cpe_mapping.json (per-asset criticality and CIA weights)",
        default="/scenario/asset_cpe_mapping.json",
    )
    parser.add_argument(
        "--no-caption",
        action="store_true",
        help="Render the detailed annotated graph without the embedded caption",
    )

    args = parser.parse_args()
    Logger.configure(config_file=args.log_config)

    controller = PostProcessingController(config_path=args.config)
    controller.run(
        graph_dir=args.graph_dir,
        work_dir=args.work_dir,
        asset_mapping_path=args.asset_cpe_mapping,
        include_legend=not args.no_caption,
    )

if __name__ == "__main__":
    main()
