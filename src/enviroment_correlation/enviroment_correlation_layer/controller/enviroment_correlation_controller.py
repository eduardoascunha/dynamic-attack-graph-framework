"""
Environment Correlation Controller.
Orchestrates correlation between assets, threat intelligence (CVEs), and STRIDE threat models.
"""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from ..utils.logger import Logger
from ..utils.settings import Settings
from ..handlers.enviroment_correlation_handler import EnviromentCorrelationHandler
from ..handlers.quality_gate_handler import QualityGateHandler
from ..handlers.stride_handler import StrideHandler
from ..models.asset_cpe_schema import AssetCpeMappingRoot
from ..models.stride_schema import StrideDefinitionRoot


class EnviromentCorrelationController:
    """
    Orchestrates environment correlation between assets and threat intelligence data.
    """

    def __init__(self, config_path: str) -> None:
        """
        Initialize controller with configuration and handlers.

        Args:
            config_path: Path to TOML configuration file.

        Raises:
            Exception: On initialization errors.
        """
        self._log = Logger.get_logger()

        try:
            self._app_config: Settings = Settings(config_path)
            self._log.debug(f"Configuration loaded from {config_path}")
        except Exception as init_error:
            self._log.error(
                f"Configuration loading failed: {init_error}", exc_info=True
            )
            raise

        try:
            self.enviroment_handler = EnviromentCorrelationHandler(
                self._app_config.DATABASE
            )
            self.quality_gate_handler = QualityGateHandler(
                self._app_config.DATABASE, self._app_config.QUALITY_GATE
            )
            self.stride_handler = StrideHandler()
        except Exception as handler_error:
            self._log.error(f"Handler initialization error: {handler_error}")
            raise

    def _load_and_validate_asset_cpe_mapping(
        self, mapping_file: Path
    ) -> AssetCpeMappingRoot:
        """
        Load and validate asset CPE mapping file.

        Args:
            mapping_file: Path to asset_cpe_mapping.json file.

        Returns:
            Validated asset CPE mapping data.

        Raises:
            FileNotFoundError: If file does not exist.
            ValidationError: If JSON structure is invalid.
            ValueError: If JSON is malformed.
        """
        if not mapping_file.exists():
            raise FileNotFoundError(f"Mapping file not found: {mapping_file}")

        self._log.debug(f"Loading asset CPE mapping from: {mapping_file}")

        try:
            with open(mapping_file, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self._log.error(f"Invalid JSON in {mapping_file}: {e}")
            raise ValueError(f"Malformed JSON in {mapping_file}: {e}")

        try:
            validated = AssetCpeMappingRoot.model_validate(data)
            self._log.info(
                f"Validated asset CPE mapping: {len(validated.assets)} asset(s)"
            )
            return validated
        except ValidationError as e:
            self._log.error(f"Asset CPE mapping validation failed: {e}")
            raise

    def _load_and_validate_stride_definition(
        self, stride_file: str, known_asset_ids: list[str]
    ) -> StrideDefinitionRoot:
        """
        Load and validate STRIDE threat definition file.

        Args:
            stride_file: Path to stride_definition.json file.
            known_asset_ids: Known asset IDs from scenario for cross-validation.

        Returns:
            Validated STRIDE definition data.

        Raises:
            FileNotFoundError: If file does not exist.
            ValidationError: If JSON structure is invalid.
            ValueError: If JSON is malformed or cross-validation fails.
        """
        stride_path = Path(stride_file)
        if not stride_path.exists():
            raise FileNotFoundError(f"STRIDE file not found: {stride_file}")

        self._log.debug(f"Loading STRIDE definition from: {stride_file}")

        try:
            with open(stride_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self._log.error(f"Invalid JSON in {stride_file}: {e}")
            raise ValueError(f"Malformed JSON in {stride_file}: {e}")

        try:
            validated = StrideDefinitionRoot.model_validate(data)

            # Internal validation: threats must reference defined STRIDE assets
            validated.validate_threat_asset_references()

            # Cross-validation: STRIDE assets must exist in scenario
            scenario_lookup = {aid.lower(): aid for aid in known_asset_ids}
            missing_assets = []

            for stride_asset in validated.assets:
                if stride_asset.name.lower() not in scenario_lookup:
                    missing_assets.append(stride_asset.name)

            if missing_assets:
                raise ValueError(
                    f"STRIDE validation failed: assets {missing_assets} not found in scenario. "
                    f"Known scenario assets: {known_asset_ids}"
                )

            self._log.info(
                f"Validated STRIDE definition: {len(validated.assets)} asset(s), "
                f"{len(validated.threats)} threat(s)"
            )
            return validated

        except ValidationError as e:
            self._log.error(f"STRIDE definition validation failed: {e}")
            raise

    def correlate_enviroment_with_threat_data(
        self, work_dir: str, registry_dir: str, stride_file: str | None = None
    ) -> str:
        """
        Correlate environment scenario with threat intelligence data.

        Reads the asset_cpe_mapping.json from work_dir, queries CVEs for every
        CPE found in each asset's services and client_software, then injects the
        resulting Prolog vulnerability statements into the nearest scenario*.P
        source file.  The enriched file is written to work_dir/scenario.P; any
        pre-existing scenario.P is archived to registry_dir with a timestamp
        before being replaced.

        When stride_file is provided the method additionally:
        1. Validates that every asset in the STRIDE definition exists in the
           scenario (matched against asset_cpe_mapping.json asset IDs).
        2. Validates that every threat in the STRIDE definition references an
           asset declared in the STRIDE assets block.
        3. Generates vulProperty / vulExists facts for each STRIDE
           threat and merges them with the CVE-derived statements.

        Args:
            work_dir (str): Directory with asset_cpe_mapping.json and scenario source.
            registry_dir (str): Directory used to archive previous scenario.P versions.
            stride_file (str | None): Optional path to a STRIDE definition JSON file.

        Returns:
            str: Absolute path to the generated scenario.P file.
        """
        work_path = Path(work_dir)
        registry_path = Path(registry_dir)

        self._log.info(f"Starting correlation in directory: {work_dir}")

        # Pre-flight quality gate: abort before any work if the threat
        # intelligence database is empty or only partially populated.
        self.quality_gate_handler.enforce()

        try:
            # Validate and load asset CPE mapping
            mapping_file = work_path / "asset_cpe_mapping.json"
            asset_mapping = self._load_and_validate_asset_cpe_mapping(mapping_file)

            # Pick the most-recently modified source scenario (excludes scenario.P
            # and any previously-mapped output files)
            scenario_files = [
                f for f in work_path.glob("scenario*.P")
                if f.name != "scenario.P" and "_mapped_" not in f.name
            ]
            if not scenario_files:
                raise FileNotFoundError(f"No scenario source file found in {work_dir}")

            # Select the most recently modified scenario file as the source
            env_file = max(scenario_files, key=lambda p: p.stat().st_mtime) 
            self._log.info(f"Using scenario source file: {env_file}")

            with open(env_file, "r") as f:
                scenario_lines = f.readlines()

            known_asset_ids = asset_mapping.get_asset_ids()

            # Collect CVE-based statements from CPE mappings
            statements_by_asset = self._collect_statements_by_asset(asset_mapping.assets)

            # Validate and process STRIDE threats if provided
            if stride_file is not None:
                stride_def = self._load_and_validate_stride_definition(
                    stride_file, known_asset_ids
                )
                stride_statements = self._collect_stride_statements(stride_def)
                for asset_id, stmts in stride_statements.items():
                    statements_by_asset.setdefault(asset_id, []).extend(stmts)

            output_file = self._generate_output_scenario(
                scenario_lines,
                statements_by_asset,
                work_path,
                registry_path,
            )

            self._log.info(f"Correlation complete. Output: {output_file}")
            return output_file

        except Exception as e:
            self._log.error(f"Correlation failed: {e}", exc_info=True)
            raise

    # ------------------------------------------------------------------
    # Statement collection
    # ------------------------------------------------------------------

    def _collect_statements_by_asset(self, assets: list) -> dict[str, list[str]]:
        """
        Query CVEs for CPEs in each asset and build Prolog statements.

        Args:
            assets: List of AssetCpeMapping Pydantic models.

        Returns:
            Mapping of asset_id to list of Prolog vulnerability statements.
        """
        statements_by_asset: dict[str, list[str]] = {}

        for asset in assets:
            self._log.debug(f"Processing asset: {asset.asset}")
            asset_statements = self._query_statements_for_asset(asset)

            if asset_statements:
                statements_by_asset[asset.asset] = asset_statements

        return statements_by_asset

    def _query_statements_for_asset(self, asset) -> list[str]:
        """
        Generate vulnerability statements for a single asset.

        Queries CVEs for all CPEs in the asset's services and client software,
        then generates Prolog statements for each CVE found.

        Args:
            asset: AssetCpeMapping Pydantic model.

        Returns:
            List of Prolog vulnerability statement strings.
        """
        statements: list[str] = []

        # Process services — network-facing, use remoteExploit
        if asset.services:
            for service in asset.services:
                self._log.debug(f"Querying CVEs for service CPE: {service.cpe}")
                cves = self.enviroment_handler.get_cves_for_cpe(service.cpe)
                if cves:
                    statements.extend(
                        self.enviroment_handler.generate_vulnerability_statements(
                            asset.asset, cves, service.service_name,
                            exploit_type="remoteExploit",
                        )
                    )

        # Process client software — user-driven, use remoteClient
        if asset.client_software:
            for client_sw in asset.client_software:
                self._log.debug(f"Querying CVEs for client CPE: {client_sw.cpe}")
                cves = self.enviroment_handler.get_cves_for_cpe(client_sw.cpe)
                if cves:
                    statements.extend(
                        self.enviroment_handler.generate_vulnerability_statements(
                            asset.asset, cves, client_sw.software_name,
                            exploit_type="remoteClient",
                        )
                    )

        return statements

    # ------------------------------------------------------------------
    # STRIDE helpers
    # ------------------------------------------------------------------

    def _collect_stride_statements(
        self, stride_def: StrideDefinitionRoot
    ) -> dict[str, list[str]]:
        """
        Convert validated STRIDE definition into Prolog statements.

        Args:
            stride_def: Validated STRIDE definition Pydantic model.

        Returns:
            Mapping of asset_id to list of Prolog statement strings.
        """
        self._log.info(f"Processing STRIDE definition: {stride_def.system}")

        statements = self.stride_handler.generate_statements(stride_def)

        total = sum(len(v) for v in statements.values())
        self._log.info(
            f"STRIDE mapping complete: {total} statement(s) across "
            f"{len(statements)} asset(s)."
        )
        return statements

    # ------------------------------------------------------------------
    # Registry helpers
    # ------------------------------------------------------------------

    def _archive_to_registry(
        self,
        output_file: Path,
        registry_path: Path,
        max_registry_size: int = 10,
    ) -> None:
        """
        Archive current scenario file to registry with UTC timestamp.

        Moves the existing mapped file (preserving its content) so a fresh
        version can be written. After archiving, removes old versions beyond
        the maximum registry size (oldest removed first).

        Args:
            output_file: Current mapped scenario file to archive.
            registry_path: Directory for storing archived versions.
            max_registry_size: Maximum number of archived versions to keep.
        """
        registry_path.mkdir(parents=True, exist_ok=True)

        stem = output_file.stem
        suffix = output_file.suffix

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archived_file = registry_path / f"{stem}_{timestamp}{suffix}"
        shutil.move(str(output_file), str(archived_file))
        self._log.info(f"Moved previous mapped scenario to registry: {archived_file}")

        # Rotate: delete archives beyond the keep limit (oldest first)
        all_archives = sorted(
            registry_path.glob(f"{stem}_*{suffix}"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in all_archives[max_registry_size:]:
            old.unlink()
            self._log.info(f"Removed oldest registry entry: {old}")

    # ------------------------------------------------------------------
    # Scenario generation
    # ------------------------------------------------------------------

    def _generate_output_scenario(
        self,
        original_lines: list,
        statements_by_asset: dict,
        work_path: Path,
        registry_path: Path,
    ) -> str:
        """
        Generate enriched Prolog scenario file with vulnerability statements.

        Vulnerability statements are appended to the end of the source
        scenario file.

        Archives any existing scenario.P before overwriting.

        Args:
            original_lines: Lines from source scenario file.
            statements_by_asset: Mapping of asset_id to Prolog statements.
            work_path: Destination directory for mapped file.
            registry_path: Registry directory for archived versions.

        Returns:
            Absolute path to generated scenario.P file.
        """
        output_lines: list[str] = list(original_lines)

        all_statements: list[str] = []
        for asset_id, statements in statements_by_asset.items():
            if statements:
                all_statements.extend(stmt + "\n" for stmt in statements)
                self._log.debug(
                    f"Appended {len(statements)} vulnerability statements "
                    f"for asset '{asset_id}'"
                )

        if all_statements and output_lines and not output_lines[-1].endswith("\n"):
            output_lines[-1] += "\n"

        if all_statements:
            if output_lines and output_lines[-1].strip():
                output_lines.append("\n")
            output_lines.extend(all_statements)

        new_content = "".join(output_lines)
        output_file = work_path / "scenario.P"

        # Archive the current file before overwriting
        if output_file.exists():
            self._archive_to_registry(output_file, registry_path)

        output_file.write_text(new_content)
        self._log.info(f"Written mapped scenario: {output_file}")

        return str(output_file)
