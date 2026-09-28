"""
Environment Correlation Handler: Maps CPEs to CVEs and generates vulnerability statements.
"""

from typing import List
from sqlalchemy import select

from ..database.schemas.cve_cpe_mapping_schema import CveCpeMappingSchema
from ..database.postgres_repository import PostgresRepository
from ..models.config.database_config import Database
from ..utils.logger import Logger


class EnviromentCorrelationHandler:
    """
    Handles environment correlation between assets, CPEs, and CVEs.
    """

    def __init__(self, db_config: Database):
        """
        Init with database config.
        Args:
            db_config (Database): Database configuration.
        """
        self._log = Logger.get_logger()
        self._db_config = db_config
                 
    def get_cves_for_cpe(self, cpe: str) -> List[str]:
        """
        Query database to get all CVEs associated with a CPE.
        Args:
            cpe (str): CPE identifier string.
        Returns:
            List[str]: List of CVE IDs.
        """
        cves = []
        try:
            with PostgresRepository(self._db_config) as repo:
                stmt = select(CveCpeMappingSchema.cve_id).where(
                    CveCpeMappingSchema.cpe == cpe
                )
                result = repo.execute_query(stmt)
                cves = [row[0] for row in result]
            
            self._log.debug(f"Found {len(cves)} CVEs for CPE: {cpe}")
        except Exception as e:
            self._log.error(f"Error querying CVEs for CPE {cpe}: {e}", exc_info=True)
        
        return cves
    
    def generate_vulnerability_statements(
        self,
        asset_id: str,
        cves: List[str],
        software: str,
        exploit_type: str = "remoteExploit",
    ) -> List[str]:
        """
        Generate Prolog vulnerability statements for an asset from CVE data.

        Produces two statements per CVE:
        - vulExists: links CVE to asset and software
        - vulProperty: exploit type and consequence

        The caller is responsible for passing the correct exploit_type:
        - ``remoteExploit`` for network services (requires networkServiceInfo
          in the scenario file to fire the MulVAL rule)
        - ``remoteClient`` for client software such as browsers or document
          readers (requires inCompetent/hasAccount in the scenario file)

        Args:
            asset_id: Asset identifier.
            cves: List of CVE IDs.
            software: Software name.
            exploit_type: MulVAL exploit type, either 'remoteExploit' or
                'remoteClient'. Defaults to 'remoteExploit'.

        Returns:
            List of Prolog statement strings.
        """
        statements = []

        for cve in cves:
            vul_exists = f"vulExists({asset_id},'{cve}',{software})."
            vul_prop = f"vulProperty('{cve}',{exploit_type},privEscalation)."
            statements.append(vul_exists)
            statements.append(vul_prop)

        return statements
