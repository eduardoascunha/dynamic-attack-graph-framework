from pydantic import BaseModel, HttpUrl, Field, SecretStr


class VulnCheck(BaseModel):
    """
    Settings for the VulnCheck API.

    Attributes:
        api_kev_endpoint (HttpUrl):
            URL endpoint for VulnCheck KEV API.
        api_nvd_endpoint (HttpUrl):
            URL endpoint for VulnCheck NVD API (includes CVE data with associated CPEs).
        api_token (SecretStr):
            Secret token used for VulnCheck API authentication.
    """

    api_kev_endpoint: HttpUrl = Field(
        default=HttpUrl("https://api.vulncheck.com/v3/backup/vulncheck-kev"),
        description="VulnCheck KEV API endpoint URL",
    )
    api_nvd_endpoint: HttpUrl = Field(
        default=HttpUrl("https://api.vulncheck.com/v3/backup/nist-nvd2"),
        description="VulnCheck NVD API endpoint URL",
    )
    api_token: SecretStr | None = Field(
        default=None, description="VulnCheck API access token; handled as a secret"
    )
