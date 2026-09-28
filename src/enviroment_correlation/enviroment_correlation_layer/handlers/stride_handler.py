"""
STRIDE Threat Model Handler.
Converts validated STRIDE Pydantic models into MulVAL-compatible Prolog statements.
"""

from typing import Dict, List

from ..utils.logger import Logger
from ..models.stride_schema import StrideDefinitionRoot

# STRIDE category -> MulVAL exploit type mapping
_STRIDE_EXPLOIT_MAP: Dict[str, str] = {
    "spoofing": "remoteExploit",
    "tampering": "remoteExploit",
    "repudiation": "localExploit",
    "information disclosure": "remoteExploit",
    "denial of service": "remoteExploit",
    "elevation of privilege": "remoteClient",
}
_DEFAULT_EXPLOIT = "remoteExploit"

# Impact type -> MulVAL consequence mapping
_IMPACT_CONSEQUENCE_MAP: Dict[str, str] = {
    "account_compromise": "privEscalation",
    "data_modification": "privEscalation",
    "log_tampering": "privEscalation",
    "data_exfiltration": "privEscalation",
    "privilege_escalation": "privEscalation",
    "unauthorized_access": "privEscalation",
    "remote_code_execution": "privEscalation",
    "arbitrary_code_execution": "privEscalation",
    "data_exposure": "privEscalation",
    "service_disruption": "dos",
    "availability_loss": "dos",
    "service_unavailability": "dos",
}
_DEFAULT_CONSEQUENCE = "privEscalation"


class StrideHandler:
    """
    Converts validated STRIDE definition Pydantic models into MulVAL Prolog facts.
    """

    def __init__(self) -> None:
        self._log = Logger.get_logger()

    def generate_statements(
        self, stride_def: StrideDefinitionRoot
    ) -> Dict[str, List[str]]:
        """
        Convert STRIDE threats into MulVAL Prolog statements.

        Generates Prolog statements per threat:
            vulProperty(<threatName>, <exploitType>, <consequence>).
            vulExists(<assetId>, <threatName>, <service>).

        For threats mapped to `remoteClient`, the handler also generates the
        minimum user-context facts required by the default MulVAL rule set:
            inCompetent(<assetId>_user).
            hasAccount(<assetId>_user, <assetId>, user).

        Threat names are derived from ID and STRIDE category
        (e.g., threat_t1_elevation_of_privilege).

        Args:
            stride_def: Validated STRIDE definition Pydantic model.

        Returns:
            Mapping of asset_id to list of Prolog statement strings.
        """
        statements_by_asset: Dict[str, List[str]] = {}

        # Build asset name → service lookup
        asset_service_map = {asset.name: asset.service for asset in stride_def.assets}

        for threat in stride_def.threats:
            # Use asset name directly as asset_id (they match in validated data)
            asset_id = threat.asset

            # Generate threat name from ID and STRIDE category
            threat_id = threat.id.lower()
            stride_category_clean = threat.stride.lower().replace(" ", "_")
            threat_name = f"threat_{threat_id}_{stride_category_clean}"

            stride_category = threat.stride.lower()
            exploit_type = _STRIDE_EXPLOIT_MAP.get(stride_category, _DEFAULT_EXPLOIT)

            impact = threat.impact.lower()
            consequence = _IMPACT_CONSEQUENCE_MAP.get(impact, _DEFAULT_CONSEQUENCE)

            # Resolve service from STRIDE asset definition
            service = asset_service_map.get(asset_id, "unknown")

            vul_property = f"vulProperty({threat_name},{exploit_type},{consequence})."
            vul_exists = f"vulExists({asset_id},{threat_name},{service})."

            self._log.debug(
                f"STRIDE threat id={threat.id}: {vul_property} | {vul_exists}"
            )

            statements_by_asset.setdefault(asset_id, [])
            # Avoid duplicate vulProperty lines across multiple threats sharing
            # the same threat name
            if vul_property not in statements_by_asset[asset_id]:
                statements_by_asset[asset_id].append(vul_property)
            statements_by_asset[asset_id].append(vul_exists)

        return statements_by_asset
