FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.8.0

COPY pyproject.toml ./

RUN poetry install --no-root --only main --no-interaction --no-ansi

COPY enviroment_correlation_layer ./enviroment_correlation_layer
COPY .config ./.config

ENV PYTHONPATH=/app

CMD ["poetry", "run", "python", "-m", "enviroment_correlation_layer", \
     "--config", ".config/config.toml", \
     "--log-config", ".config/logging.ini", \
     "--work-dir", "/app/enviroment", \
     "--registry-dir", "/app/enviroment/registry", \
     "--stride-file", "/app/enviroment/stride_definition.json"]