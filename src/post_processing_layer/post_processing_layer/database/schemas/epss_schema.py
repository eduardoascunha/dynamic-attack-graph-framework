"""
SQLAlchemy ORM schema for the threat_intel.epss table.
Stores FIRST EPSS exploitation probability scores per CVE.
"""

from sqlalchemy import Column, DateTime, Float, String

from ..base import Base


class EpssSchema(Base):
    __tablename__ = "epss"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(String(50), primary_key=True)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    created_at = Column(DateTime)
