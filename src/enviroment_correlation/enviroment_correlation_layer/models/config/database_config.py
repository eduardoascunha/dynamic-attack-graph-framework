"""Database configuration model."""

from pydantic import BaseModel, Field, SecretStr


class Database(BaseModel):
    """
    Database configuration settings.
    Contains connection parameters for PostgreSQL database.
    """

    dbname: SecretStr | None = Field(default=None, description="Database name.")
    user: SecretStr | None = Field(default=None, description="DB username.")
    password: SecretStr | None = Field(default=None, description="DB password.")
    host: SecretStr | None = Field(default=None, description="DB host address.")
    dbdriver: str = Field(default="psycopg", description="DB driver.")
    port: int = Field(default=5432, ge=0, le=65535, description="DB port.")
    options: str | None = Field(default=None, description="Extra connection options.")
    sslmode: str | None = Field(default="require", description="SSL mode.")
    sslrootcert: str | None = Field(default=None, description="SSL root cert path.")
