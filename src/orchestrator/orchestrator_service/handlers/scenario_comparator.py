"""Scenario Comparator: Compares MulVAL scenario files to detect critical changes."""

from typing import Set
import re
import hashlib

from ..utils.logger import Logger


class ScenarioComparator:
    """Compares two scenario files to detect critical changes like new vulnerabilities."""

    def __init__(self):
        """Initialize the scenario comparator."""
        self._log = Logger.get_logger()

    def has_critical_changes(self, old_scenario: str, new_scenario: str) -> bool:
        """
        Check if there are critical changes between two scenarios.
        
        Uses a two-phase approach:
        1. Quick hash comparison - if hashes match, no changes
        2. Detailed comparison - if hashes differ, analyze what changed
        
        Critical changes include additions, removals, or modifications to
        scenario facts such as vulnerabilities, attack goals, connectivity,
        and service configuration.
        
        Args:
            old_scenario: Path to old scenario file.
            new_scenario: Path to new scenario file.
            
        Returns:
            True if critical changes detected, False otherwise.
        """
        try:
            # Quick hash comparison
            old_hash = self._compute_file_hash(old_scenario)
            new_hash = self._compute_file_hash(new_scenario)
            
            if old_hash == new_hash:
                self._log.info("Scenarios are identical (hash match)")
                return False
            
            self._log.debug(f"Hash mismatch: {old_hash[:12]}... != {new_hash[:12]}...")
            
            old_facts = self._extract_facts(old_scenario)
            new_facts = self._extract_facts(new_scenario)
            added_facts = new_facts - old_facts
            removed_facts = old_facts - new_facts

            if added_facts or removed_facts:
                self._log.info(
                    "Detected %d added and %d removed scenario facts",
                    len(added_facts),
                    len(removed_facts),
                )
                self._log.debug("Added facts: %s", added_facts)
                self._log.debug("Removed facts: %s", removed_facts)
                return True
            
            # Hash differs but no critical changes detected
            self._log.info("No critical changes detected")
            return False
            
        except Exception as e:
            self._log.error(f"Error comparing scenarios: {e}", exc_info=True)
            # If comparison fails, assume there are changes to be safer
            return True
    
    def _compute_file_hash(self, file_path: str) -> str:
        """
        Compute SHA-256 hash of a file for efficient comparison.
        
        Args:
            file_path: Path to the file.
            
        Returns:
            Hexadecimal hash string.
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read in chunks for memory efficiency with large files
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def _extract_facts(self, scenario_file: str) -> Set[str]:
        """
        Extract normalized single-line Prolog facts from a scenario file.
        
        Args:
            scenario_file: Path to scenario file.
            
        Returns:
            Set of scenario facts without comments or whitespace differences.
        """
        facts = set()
        
        with open(scenario_file, 'r') as f:
            for line in f:
                statement = line.split('%', maxsplit=1)[0].strip()
                match = re.fullmatch(r'([a-z][A-Za-z0-9_]*)\s*\((.*)\)\.', statement)
                if match:
                    predicate, arguments = match.groups()
                    normalized_arguments = re.sub(r'\s+', '', arguments)
                    facts.add(f"{predicate}({normalized_arguments})")
        
        return facts
