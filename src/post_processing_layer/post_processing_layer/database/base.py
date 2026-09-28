"""
SQLAlchemy singleton declarative base config.
Ensures a single ORM base instance to avoid metadata conflicts.
"""

from typing import ClassVar, Optional, Type

from sqlalchemy.orm import DeclarativeMeta, declarative_base


class BaseSingleton:
    """
    Singleton for SQLAlchemy declarative_base.
    """

    __instance: ClassVar[Optional[DeclarativeMeta]] = None

    @classmethod
    def get_base(cls: Type["BaseSingleton"]) -> DeclarativeMeta:
        """
        Get singleton declarative_base instance.
        """
        if cls.__instance is None:
            cls.__instance = declarative_base()
        return cls.__instance


Base: DeclarativeMeta = BaseSingleton.get_base()
