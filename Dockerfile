FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

COPY pyproject.toml README.md LICENSE HOWTO.md config.yaml ./
COPY *.py ./
COPY templates/ templates/
RUN pip install --no-cache-dir -e . \
    && useradd --system --no-create-home app

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8080'), timeout=3)"]

# One worker: poller threads and event buffers are per-process state.
CMD ["sh", "-c", "exec gunicorn -b 0.0.0.0:${PORT:-8080} -w 1 --threads 8 --timeout 60 app:app"]
