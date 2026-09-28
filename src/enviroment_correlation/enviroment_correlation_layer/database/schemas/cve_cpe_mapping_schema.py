from sqlalchemy import Column, String, ForeignKey
from ..base import Base


class CveCpeMappingSchema(Base):
    """
    ORM model for persisting CVE-CPE mappings into the database.

    :param Base: SQLAlchemy declarative base.

    Attributes:
        cve_id: The CVE identifier (foreign key to cves table).
        cpe: The CPE identifier string.
    """

    __tablename__ = "cve_cpe_mapping"
    __table_args__ = {"schema": "threat_intel"}

    cve_id = Column(
        String(50),
        ForeignKey("threat_intel.cves.cve_id"),
        primary_key=True,
        nullable=False,
    )
    cpe = Column(String(300), primary_key=True, nullable=False)

    def __repr__(self) -> str:
        return f"<CveCpeMappingSchema(cve_id='{self.cve_id}', cpe='{self.cpe}')>"

