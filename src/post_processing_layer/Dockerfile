FROM python:3.14-slim

WORKDIR /app

# Install Graphviz for rendering attack graph visualizations
RUN apt-get update && \
    apt-get install -y --no-install-recommends graphviz && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.0

COPY pyproject.toml ./

RUN poetry install --no-root --only main --no-interaction --no-ansi

COPY post_processing_layer ./post_processing_layer
COPY .config ./.config

ENV PYTHONPATH=/app

CMD ["poetry", "run", "python", "-m", "post_processing_layer", \
     "--config", ".config/config.toml", \
     "--log-config", ".config/logging.ini", \
     "--graph-dir", "/gen_graph", \
     "--work-dir", "/post_processing"]