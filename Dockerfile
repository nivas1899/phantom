FROM python:3.12-slim

LABEL maintainer="PHANTOM Team"
LABEL description="PHANTOM — Inter-Layer Semantic Gap Exploitation Framework"

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

RUN mkdir -p /output

ENV TERM=xterm-256color

EXPOSE 8080

ENTRYPOINT ["python", "cli.py"]
CMD ["web", "--port", "8080"]
