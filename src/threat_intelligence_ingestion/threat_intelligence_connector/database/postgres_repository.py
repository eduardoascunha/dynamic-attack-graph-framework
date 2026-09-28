"""
PostgreSQL repository for threat intelligence data.
Manages DB operations and table creation via SQLAlchemy ORM.
"""

from typing import Any, Sequence, Literal
from types import TracebackType

from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import URL
from sqlalchemy.schema import DDL
from sqlalchemy.dialects.postgresql import insert

from ..utils.logger import Logger
from ..models.config.database_config import Database
from .base import Base


class PostgresRepository:
    """
    Manages PostgreSQL operations via SQLAlchemy ORM.
    Supports truncate and bulk insert. Tables auto-created if missing.
    Usage:
        with PostgresRepository(settings) as repo:
            repo.truncate_table(ModelClass)
            repo.insert_many([obj1, obj2])
    """

    _CONTEXT_MANAGER_ERROR = "PostgresRepository must be used as a context manager"

    def __init__(self, settings: Database) -> None:
        """
        Initialize connection params for SQLAlchemy engine (no engine/session yet).
        Args:
            settings: DB config (host, port, dbname, user, password, etc).
        """
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
        connect_args = {"sslmode": sslmode}
        if sslrootcert:
            connect_args["sslrootcert"] = sslrootcert
        self.__connection_arguments = connect_args

    def __enter__(self) -> "PostgresRepository":
        """
        Create engine, sessionmaker, and tables. Returns self.
        """
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
        """
        Dispose engine on exit. Always propagates exceptions.
        """
        try:
            self.__engine.dispose()
            self.__logger.debug("Engine disposed")
        except SQLAlchemyError:
            self.__logger.warning("Failed to dispose engine", exc_info=True)

        return False

    def truncate_table(self, model_class: type) -> None:
        """
        Truncate a table. Must be called inside context manager.
        Args:
            model_class: ORM model class.
        Raises:
            RuntimeError: If not in context manager.
            SQLAlchemyError: On truncate failure.
        """
        if not hasattr(self, "_PostgresRepository__engine"):
            raise RuntimeError(self._CONTEXT_MANAGER_ERROR)

        mapper = inspect(model_class)
        table = mapper.local_table

        self.__logger.debug("Truncating %s.%s", table.schema, table.name)

        try:
            with self.session() as session:
                truncate_stmt = DDL(f"TRUNCATE TABLE {table.fullname} CASCADE")  # type: ignore[no-untyped-call]
                session.execute(truncate_stmt)
                session.commit()
            self.__logger.info(
                "Truncate successful for %s.%s",
                table.schema,
                table.name,
            )
        except SQLAlchemyError as e:
            self.__logger.error("Truncate failed: %s", e)
            raise

    def insert_many(self, objs: Sequence[Any]) -> None:
        """
        Bulk insert ORM objects. Must be called inside context manager.
        Args:
            objs: List of ORM model instances.
        Raises:
            RuntimeError: If not in context manager.
            SQLAlchemyError: On insert failure.
        """
        if not hasattr(self, "_PostgresRepository__engine"):
            raise RuntimeError(self._CONTEXT_MANAGER_ERROR)

        if not objs:
            self.__logger.warning("Empty object list provided to insert_many")
            return

        self.__logger.debug("Bulk inserting %d objects", len(objs))
        try:
            with self.session() as session:
                session.add_all(objs)
                session.commit()
            self.__logger.debug("Bulk insert successful for %d objects", len(objs))
        except SQLAlchemyError as e:
            self.__logger.error("Bulk insert failed: %s", e)
            raise

    def bulk_insert_mappings_on_conflict_do_nothing(
        self, model_class: type, mappings: list[dict[str, Any]], chunk_size: int = 1000
    ) -> None:
        """
        Ultra-efficient bulk insert using INSERT ... ON CONFLICT DO NOTHING.
        Uses raw dict mappings instead of ORM objects for better performance.
        Must be called inside context manager.
        Args:
            model_class: ORM model class.
            mappings: List of dicts with column names as keys.
            chunk_size: Number of records to insert per batch (default: 1000).
        Raises:
            RuntimeError: If not in context manager.
            SQLAlchemyError: On insert failure.
        """
        if not hasattr(self, "_PostgresRepository__engine"):
            raise RuntimeError(self._CONTEXT_MANAGER_ERROR)

        if not mappings:
            self.__logger.warning("Empty mappings list provided")
            return

        self.__logger.debug(
            "Bulk inserting %d mappings for %s with ON CONFLICT DO NOTHING (chunk_size=%d)",
            len(mappings),
            model_class.__name__,
            chunk_size
        )
        
        try:
            mapper = inspect(model_class)
            table = mapper.local_table

            with self.session() as session:
                # Process in chunks to avoid memory and parameter limits
                for i in range(0, len(mappings), chunk_size):
                    chunk = mappings[i:i + chunk_size]
                    
                    # Use PostgreSQL INSERT ... ON CONFLICT DO NOTHING
                    stmt = insert(table).on_conflict_do_nothing()
                    session.execute(stmt, chunk)

                session.commit()
            self.__logger.debug(
                "Bulk insert with ON CONFLICT DO NOTHING successful for %d mappings",
                len(mappings)
            )
        except SQLAlchemyError as e:
            self.__logger.error("Bulk insert mappings with ON CONFLICT DO NOTHING failed: %s", e)
            raise

    def upsert_many(
        self, objs: Sequence[Any], constraint: str | None = None, chunk_size: int = 1000
    ) -> None:
        """
        Bulk upsert ORM objects using INSERT ... ON CONFLICT DO UPDATE.
        If a record exists, it updates all non-primary-key columns.
        If it doesn't exist, it inserts a new record.
        Must be called inside context manager.
        Args:
            objs: List of ORM model instances.
            constraint: Name of constraint to check (e.g., 'pk_cve', 'cve_pkey').
                       If None, uses the primary key constraint.
            chunk_size: Number of records to process per batch (default: 1000).
        Raises:
            RuntimeError: If not in context manager.
            SQLAlchemyError: On upsert failure.
        """
        if not hasattr(self, "_PostgresRepository__engine"):
            raise RuntimeError(self._CONTEXT_MANAGER_ERROR)

        if not objs:
            self.__logger.warning("Empty object list provided to upsert_many")
            return

        model_class = type(objs[0])
        mapper = inspect(model_class)
        table = mapper.local_table

        # Get primary key columns
        pk_cols = [col.name for col in table.primary_key.columns]
        if not pk_cols:
            raise ValueError(f"Table {table.name} has no primary key defined")

        self.__logger.debug(
            "Upserting %d objects for %s (chunk_size=%d)",
            len(objs),
            model_class.__name__,
            chunk_size
        )

        try:
            with self.session() as session:
                # Process in chunks to avoid memory limits
                for i in range(0, len(objs), chunk_size):
                    chunk = objs[i:i + chunk_size]
                    
                    # Convert ORM objects to dict mappings
                    mappings = [
                        {col.name: getattr(obj, col.name) for col in table.columns}
                        for obj in chunk
                    ]

                    # Build INSERT statement
                    stmt = insert(table)
                    
                    # Add ON CONFLICT clause
                    if constraint:
                        stmt = stmt.on_conflict_do_update(
                            constraint=constraint,
                            set_={col.name: stmt.excluded[col.name] for col in table.columns if col.name not in pk_cols}
                        )
                    else:
                        # Use primary key columns for conflict detection
                        stmt = stmt.on_conflict_do_update(
                            index_elements=pk_cols,
                            set_={col.name: stmt.excluded[col.name] for col in table.columns if col.name not in pk_cols}
                        )
                    
                    session.execute(stmt, mappings)

                session.commit()
            
            self.__logger.info(
                "Upsert successful for %d %s objects",
                len(objs),
                model_class.__name__
            )
        except SQLAlchemyError as e:
            self.__logger.error("Upsert failed: %s", e)
            raise