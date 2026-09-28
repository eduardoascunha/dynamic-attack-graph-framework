"""
SQLAlchemy ORM schema for the threat_intel.kev table.
Stores CISA Known Exploited Vulnerabilities catalogue entries.
"""

from sqlalchemy import Boolean, Column, Date, DateTime, String

from ..base import Base


class KevSchema(Base):
    __tablename__ = "kev"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(String(50), primary_key=True)
    product = Column(String(200))
    date_added = Column(Date)
    known_ransomware_use = Column(Boolean, default=False)
    created_at = Column(DateTime)
