FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    autoconf \
    bison \
    flex \
    curl \
    wget \
    graphviz \
    default-jdk \
    texlive-font-utils \
    file \
    && rm -rf /var/lib/apt/lists/*

# Build XSB Prolog from source (tar from SourceForge)
WORKDIR /tmp
RUN wget -q --tries=3 \
        "https://sourceforge.net/projects/xsb/files/xsb/5.0%20(Green%20Tea)/XSB-5.0.tar.gz/download" \
        -O XSB.tar.gz \
    && tar -xzf XSB.tar.gz \
    && rm XSB.tar.gz \
    && cd XSB/build \
    && ./configure \
    && ./makexsb

ENV PATH="${PATH}:/tmp/XSB/bin"

WORKDIR /mulval
COPY mulval/ ./
RUN make

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.8.0

COPY orchestrator/pyproject.toml ./

RUN poetry install --no-root --only main --no-interaction --no-ansi

COPY orchestrator/orchestrator_service ./orchestrator_service
COPY orchestrator/.config ./.config

ENV MULVALROOT=/mulval
ENV PATH="${PATH}:/mulval/bin:/mulval/utils"

CMD ["poetry", "run", "python", "-m", "orchestrator_service", \
     "--config", ".config/config.toml", \
     "--log-config", ".config/logging.ini", \
     "--mapped-scenario", "/output/scenario.P", \
     "--graph-dir", "/gen_graph"]