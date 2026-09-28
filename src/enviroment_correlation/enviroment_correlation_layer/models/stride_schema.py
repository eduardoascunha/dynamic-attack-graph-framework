"""
Pydantic models for STRIDE threat definition JSON schema validation.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


# Valid STRIDE categories (case-insensitive)
VALID_STRIDE_CATEGORIES = {
    "spoofing",
    "tampering",
    "repudiation",
    "information disclosure",
    "denial of service",
    "elevation of privilege",
}


class StrideAsset(BaseModel):
    """Asset definition in STRIDE threat model."""
    
    name: str = Field(..., description="Asset name matching scenario asset ID")
    service: str = Field(..., description="Primary service name for the asset")
    
    @field_validator("name", "service")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure fields are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class StrideThreat(BaseModel):
    """Individual STRIDE threat definition."""
    
    id: str = Field(..., description="Unique threat identifier (e.g., T1, T2)")
    stride: str = Field(..., description="STRIDE category")
    asset: str = Field(..., description="Target asset name")
    impact: str = Field(..., description="Impact type (e.g., remote_code_execution)")
    description: Optional[str] = Field(default=None, description="Human-readable threat description")
    mitre_attack: Optional[str] = Field(default=None, description="MITRE ATT&CK technique reference")
    
    @field_validator("id", "stride", "asset", "impact")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure required fields are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()
    
    @field_validator("stride")
    @classmethod
    def validate_stride_category(cls, v: str) -> str:
        """Validate STRIDE category is valid."""
        if v.lower() not in VALID_STRIDE_CATEGORIES:
            raise ValueError(
                f"Invalid STRIDE category '{v}'. "
                f"Must be one of: {', '.join(sorted(VALID_STRIDE_CATEGORIES))}"
            )
        return v


class StrideDefinitionRoot(BaseModel):
    """Root schema for stride_definition.json file."""
    
    system: str = Field(..., description="System or scenario name")
    assets: List[StrideAsset] = Field(..., description="List of assets in threat model")
    threats: List[StrideThreat] = Field(..., description="List of STRIDE threats")
    
    @field_validator("system")
    @classmethod
    def validate_system_not_empty(cls, v: str) -> str:
        """Ensure system name is not empty."""
        if not v or not v.strip():
            raise ValueError("System name cannot be empty")
        return v.strip()
    
    @field_validator("assets")
    @classmethod
    def validate_unique_asset_names(cls, v: List[StrideAsset]) -> List[StrideAsset]:
        """Ensure all asset names are unique."""
        asset_names = [a.name for a in v]
        duplicates = [name for name in asset_names if asset_names.count(name) > 1]
        if duplicates:
            raise ValueError(f"Duplicate asset names found: {set(duplicates)}")
        return v
    
    @field_validator("threats")
    @classmethod
    def validate_unique_threat_ids(cls, v: List[StrideThreat]) -> List[StrideThreat]:
        """Ensure all threat IDs are unique."""
        threat_ids = [t.id for t in v]
        duplicates = [tid for tid in threat_ids if threat_ids.count(tid) > 1]
        if duplicates:
            raise ValueError(f"Duplicate threat IDs found: {set(duplicates)}")
        return v
    
    def get_asset_names(self) -> List[str]:
        """Return list of all asset names."""
        return [asset.name for asset in self.assets]
    
    def validate_threat_asset_references(self) -> None:
        """Validate that all threats reference defined assets."""
        asset_names = set(self.get_asset_names())
        undefined_refs = [
            f"threat {t.id} references '{t.asset}'"
            for t in self.threats
            if t.asset not in asset_names
        ]
        if undefined_refs:
            raise ValueError(
                f"Invalid asset references in threats: {', '.join(undefined_refs)}"
            )
