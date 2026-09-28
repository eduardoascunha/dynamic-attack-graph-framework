"""
SQLAlchemy ORM schema for the threat_intel.cves table.
Stores CVE base metadata including CVSSv3.1 scores.
"""

from sqlalchemy import Column, DateTime, Float, String

from ..base import Base


class CvesSchema(Base):
    __tablename__ = "cves"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(String(50), primary_key=True)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    cvss_score_3_1 = Column(Float)
    cvss_vector_3_1 = Column(String(200))
    created_at = Column(DateTime)
