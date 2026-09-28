"""
Pydantic models for asset CPE mapping JSON schema validation.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class ServiceMapping(BaseModel):
    """Service with CPE mapping."""
    
    service_name: str = Field(..., description="Name of the service (e.g., httpd, nginx)")
    cpe: str = Field(..., description="CPE 2.3 identifier string")
    
    @field_validator("cpe")
    @classmethod
    def validate_cpe_format(cls, v: str) -> str:
        """Validate CPE format starts with cpe:2.3:"""
        if not v.startswith("cpe:2.3:"):
            raise ValueError(f"CPE must start with 'cpe:2.3:', got: {v}")
        return v


class ClientSoftwareMapping(BaseModel):
    """Client software with CPE mapping."""
    
    software_name: str = Field(..., description="Name of the client software (e.g., acrobat, ie)")
    cpe: str = Field(..., description="CPE 2.3 identifier string")
    
    @field_validator("cpe")
    @classmethod
    def validate_cpe_format(cls, v: str) -> str:
        """Validate CPE format starts with cpe:2.3:"""
        if not v.startswith("cpe:2.3:"):
            raise ValueError(f"CPE must start with 'cpe:2.3:', got: {v}")
        return v


class AssetCpeMapping(BaseModel):
    """Asset with its CPE mappings for services and client software."""
    
    asset: str = Field(..., description="Unique asset identifier")
    services: Optional[List[ServiceMapping]] = Field(default=None, description="List of services running on the asset")
    client_software: Optional[List[ClientSoftwareMapping]] = Field(default=None, description="List of client software on the asset")
    
    @field_validator("asset")
    @classmethod
    def validate_asset_not_empty(cls, v: str) -> str:
        """Ensure asset ID is not empty."""
        if not v or not v.strip():
            raise ValueError("Asset ID cannot be empty")
        return v.strip()
    
    def has_cpe_mappings(self) -> bool:
        """Check if asset has any CPE mappings."""
        return bool(self.services or self.client_software)


class AssetCpeMappingRoot(BaseModel):
    """Root schema for asset_cpe_mapping.json file."""
    
    assets: List[AssetCpeMapping] = Field(..., description="List of assets with CPE mappings")
    
    @field_validator("assets")
    @classmethod
    def validate_unique_assets(cls, v: List[AssetCpeMapping]) -> List[AssetCpeMapping]:
        """Ensure all asset IDs are unique."""
        asset_ids = [a.asset for a in v]
        duplicates = [aid for aid in asset_ids if asset_ids.count(aid) > 1]
        if duplicates:
            raise ValueError(f"Duplicate asset IDs found: {set(duplicates)}")
        return v
    
    def get_asset_ids(self) -> List[str]:
        """Return list of all asset IDs."""
        return [asset.asset for asset in self.assets]
