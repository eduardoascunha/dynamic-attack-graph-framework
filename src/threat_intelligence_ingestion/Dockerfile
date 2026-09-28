FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.8.0

COPY pyproject.toml ./

RUN poetry install --no-root --only main --no-interaction --no-ansi

COPY threat_intelligence_connector ./threat_intelligence_connector
COPY .config ./.config

ENV PYTHONPATH=/app

CMD ["poetry", "run", "python", "-m", "threat_intelligence_connector", "--config", ".config/config.toml", "--log-config", ".config/logging.ini"]