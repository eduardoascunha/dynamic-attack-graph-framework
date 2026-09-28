from pydantic import BaseModel


class VulncheckReportedExploitationItem(BaseModel):
    """Minimal exploitation report info (needed for validation)."""

    url: str
    date_added: str


class KEV(BaseModel):
    """
    Simplified Known Exploited Vulnerability (KEV) entry from VulnCheck API.

    Only includes fields actually used in the database schema.
    """

    cve: list[str]
    product: str = ""
    date_added: str = ""
    knownRansomwareCampaignUse: str = ""
    vulncheck_reported_exploitation: list[VulncheckReportedExploitationItem] | None = (
        None
    )
