FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY skullflash/ ./skullflash/
COPY templates/  ./templates/
COPY config/     ./config/
COPY sample/     ./sample/

ENTRYPOINT ["skull-flash"]
