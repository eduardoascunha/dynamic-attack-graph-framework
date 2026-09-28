"""
CVSS v3.1 vector parser for extracting CIA triad impact metrics.

Parses CVSS:3.1/* vector strings to extract Confidentiality, Integrity, and
Availability impact ratings for use in risk prioritization.
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional

from .logger import Logger


@dataclass
class CIAImpact:
    """
    CIA triad impact values from CVSS: 0.0=None, 0.5=Low, 1.0=High.
    """

    confidentiality: float = 0.0
    integrity: float = 0.0
    availability: float = 0.0

    def is_neutral(self) -> bool:
        """Return True if all CIA impacts are zero."""
        return (
            self.confidentiality <= 0
            and self.integrity <= 0
            and self.availability <= 0
        )


class CVSSParser:
    """
    Parse CVSS v3.1 vector strings and extract CIA impact metrics.

    Example: CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L
             Extracts: C:L (0.5), I:N (0.0), A:L (0.5)
    """

    # CVSS v3.1 impact rating mappings
    _IMPACT_MAP = {
        "N": 0.0,  # None
        "L": 0.5,  # Low
        "H": 1.0,  # High
    }

    def __init__(self) -> None:
        self._log: logging.Logger = Logger.get_logger()
        # Regex to extract CIA values from CVSS vector
        self._cia_pattern = re.compile(r"/C:([NLH])/I:([NLH])/A:([NLH])")

    def parse(self, cvss_vector: Optional[str]) -> CIAImpact:
        """
        Extract CIA impact values from CVSS v3.1 vector string.
        
        Returns CIAImpact(0, 0, 0) if vector is None or unparseable.
        """
        if not cvss_vector:
            self._log.debug("No CVSS vector, returning neutral CIA")
            return CIAImpact()

        match = self._cia_pattern.search(cvss_vector)
        if not match:
            self._log.warning("Cannot parse CIA from: %s", cvss_vector)
            return CIAImpact()

        c_raw, i_raw, a_raw = match.groups()
        return CIAImpact(
            confidentiality=self._IMPACT_MAP.get(c_raw, 0.0),
            integrity=self._IMPACT_MAP.get(i_raw, 0.0),
            availability=self._IMPACT_MAP.get(a_raw, 0.0),
        )
