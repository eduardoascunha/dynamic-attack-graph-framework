from datetime import datetime

from sqlalchemy import Column, DateTime, Float, String

from ..base import Base


class EpssSchema(Base):
    """
    ORM model for persisting EPSS data into the database.

    Attributes:
        cve_id: The unique identifier for the CVE (primary key).
        epss_score: The EPSS score indicating the likelihood of exploitation.
        epss_percentile: The percentile rank of the EPSS score.
        created_at: Timestamp when the entry was created in the database.
    """

    __tablename__ = "epss"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(String(50), primary_key=True, nullable=False, index=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    created_at = Column(DateTime, nullable=True, default=datetime.now)

    def __repr__(self) -> str:
        """String representation of the EPSS entry."""
        return f"<EpssSchema(cve_id='{self.cve_id}', epss={self.epss_score})>"
