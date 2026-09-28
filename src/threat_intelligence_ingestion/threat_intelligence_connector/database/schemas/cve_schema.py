from datetime import datetime

from sqlalchemy import Column, DateTime, Float, String, TIMESTAMP

from ..base import Base


class CveSchema(Base):
    """
    ORM model for persisting CVE data into the database.

    Attributes:
        cve_id: The unique identifier of the CVE (primary key).
        published_date: Timestamp when the CVE was published.
        last_modified_date: Timestamp when the CVE was last modified.
        cvss_score_3_1: CVSS v3.1 (Common Vulnerability Scoring System version 3.1) score.
        cvss_vector_3_1: CVSS v3.1 vector string.
        created_at: Timestamp when the entry was created in the database.
    """

    __tablename__ = "cves"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(String(50), primary_key=True, nullable=False, index=True)
    published_date = Column(TIMESTAMP, nullable=True)
    last_modified_date = Column(TIMESTAMP, nullable=True)
    cvss_score_3_1 = Column(Float, nullable=True)
    cvss_vector_3_1 = Column(String(200), nullable=True)
    created_at = Column(DateTime, nullable=True, default=datetime.now)

    def __repr__(self) -> str:
        return f"<CveSchema(cve_id='{self.cve_id}')>"
