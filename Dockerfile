# One image for the API, the Celery workers and the migration job.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UPLOAD_DIR=/data/uploads

# git: linking repositories as code sources
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data/uploads \
    && chown -R sentinel:sentinel /data
COPY --chown=sentinel:sentinel . .
USER sentinel

EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${API_WORKERS:-2} --proxy-headers"]
