from pydantic import BaseModel


class CvssDataV3(BaseModel):
    """CVSS v3.x data (works for both 3.0 and 3.1)."""

    baseScore: float
    vectorString: str


class CvssMetricV3Item(BaseModel):
    """CVSS v3.x metric item."""

    type: str
    cvssData: CvssDataV3


class Metrics(BaseModel):
    """CVSS metrics container."""

    cvssMetricV30: list[CvssMetricV3Item] | None = None
    cvssMetricV31: list[CvssMetricV3Item] | None = None


class Cve(BaseModel):
    """CVE entry with minimal required fields."""

    id: str
    published: str
    lastModified: str
    metrics: Metrics
    vcVulnerableCPEs: list[str] | None = None

    def get_cvss30_metric(self) -> CvssMetricV3Item | None:
        """Get CVSS v3.0 metric, preferring Primary type."""
        if not self.metrics.cvssMetricV30:
            return None
        # Try to find Primary metric first
        for metric in self.metrics.cvssMetricV30:
            if metric.type == "Primary":
                return metric
        return self.metrics.cvssMetricV30[0]

    def get_cvss31_metric(self) -> CvssMetricV3Item | None:
        """Get CVSS v3.1 metric, preferring Primary type."""
        if not self.metrics.cvssMetricV31:
            return None
        # Try to find Primary metric first
        for metric in self.metrics.cvssMetricV31:
            if metric.type == "Primary":
                return metric
        return self.metrics.cvssMetricV31[0]


class Vulnerability(BaseModel):
    """Vulnerability container."""

    cve: Cve


class NvdCve(BaseModel):
    """NVD CVE API response structure."""

    vulnerabilities: list[Vulnerability]
