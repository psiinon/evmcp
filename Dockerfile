FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    iputils-ping \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir starlette uvicorn requests lxml

COPY server.py .
COPY tools/ tools/
COPY data/ data/
COPY flag.txt .

EXPOSE 8000

ENTRYPOINT ["python", "server.py"]
