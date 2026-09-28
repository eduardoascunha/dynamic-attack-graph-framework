"""
PostgreSQL repository for the post-processing layer.
Manages engine lifecycle and exposes session access for read queries.
"""

from types import TracebackType
from typing import Any, Literal, Sequence

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from ..models.config.database_config import Database
from ..utils.logger import Logger
from .base import Base

class PostgresRepository:
    """
    Manages PostgreSQL operations via SQLAlchemy ORM.

    Usage::

        with PostgresRepository(settings) as repo:
            # Execute a read query
            rows = repo.execute_query(select(EpssSchema).where(...))
            
            # Or use session directly for complex operations
            with repo.session() as session:
                rows = session.execute(select(EpssSchema).where(...)).fetchall()
    """

    _CONTEXT_MANAGER_ERROR = "PostgresRepository must be used as a context manager"

    def __init__(self, settings: Database) -> None:
        self.__logger = Logger.get_logger()

        if (
            settings.host is None
            or settings.dbname is None
            or settings.user is None
            or settings.password is None
        ):
            raise ValueError("Database connection parameters are incomplete")

        host = settings.host.get_secret_value()
        port = settings.port
        dbname = settings.dbname.get_secret_value()
        user = settings.user.get_secret_value()
        password = settings.password.get_secret_value()
        dbdriver = settings.dbdriver
        sslmode = settings.sslmode
        sslrootcert = settings.sslrootcert

        self.__logger.debug(
            "Configured DB URL on %s:%s/%s (sslmode=%s)", host, port, dbname, sslmode
        )
        self.__url = URL.create(
            drivername=f"postgresql+{dbdriver}",
            username=user,
            password=password,
            host=host,
            port=port,
            database=dbname,
        )
        connect_args: dict[str, Any] = {"sslmode": sslmode}
        if sslrootcert:
            connect_args["sslrootcert"] = sslrootcert
        self.__connection_arguments = connect_args

    def __enter__(self) -> "PostgresRepository":
        try:
            self.__engine = create_engine(
                self.__url,
                future=True,
                connect_args=self.__connection_arguments,
                echo=False,
            )
            self.session = sessionmaker(bind=self.__engine, future=True)
            Base.metadata.create_all(self.__engine)
        except SQLAlchemyError as e:
            self.__logger.critical("Engine creation or table setup failed: %s", e)
            raise
        self.__logger.debug("Engine and tables ready")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            self.__engine.dispose()
            self.__logger.debug("Engine disposed")
        except SQLAlchemyError:
            self.__logger.warning("Failed to dispose engine", exc_info=True)
        return False

    def execute_query(self, stmt: Any) -> Sequence[Any]:
        """
        Execute a SELECT query and return all results.
        Must be called inside context manager.

        Args:
            stmt: SQLAlchemy select statement to execute.

        Returns:
            Sequence of result rows.

        Raises:
            RuntimeError: If called outside of context manager.
            SQLAlchemyError: If query execution fails.
        """
        if not hasattr(self, "_PostgresRepository__engine"):
            raise RuntimeError(self._CONTEXT_MANAGER_ERROR)

        try:
            with self.session() as session:
                result = session.execute(stmt).fetchall()
            return result
        except SQLAlchemyError as e:
            self.__logger.error("Query execution failed: %s", e)
            raise

    