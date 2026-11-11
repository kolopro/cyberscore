FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# libatomic1 is required by Playwright's Node.js binary (missing from slim).
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
 && rm -rf /var/lib/apt/lists/*

# Python deps + Playwright Chromium (for the URL-check page preview).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt playwright \
 && playwright install --with-deps chromium

# App code
COPY . .

EXPOSE 8000

# One worker is plenty for a small box; Chromium screenshots run one at a time.
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
