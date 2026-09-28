from datetime import datetime

from sqlalchemy import Boolean, Column, Date, DateTime, String

from ..base import Base


class KevSchema(Base):
    """
    ORM model for persisting KEV data into the database.

    Attributes:
        cve_id: The CVE identifier for the vulnerability (primary key).
        product: The product associated with the vulnerability.
        date_added: The date the vulnerability was added.
        known_ransomware_use: Flag indicating if used in ransomware campaigns.
        created_at: Timestamp when the entry was created in the database.
    """

    __tablename__ = "kev"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(String(50), primary_key=True, nullable=False, index=True)
    product = Column(String(200), nullable=True)
    date_added = Column(Date, nullable=True)
    known_ransomware_use = Column(Boolean, nullable=True, default=False)
    created_at = Column(DateTime, nullable=True, default=datetime.now)

    def __repr__(self) -> str:
        """String representation of the KEV entry."""
        return f"<KevSchema(cve_id='{self.cve_id}', product='{self.product}')>"
