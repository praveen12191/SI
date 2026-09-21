FROM python:3.12-slim

# The slim DuckDB file is baked into the image: no external database, no
# cold-start data load, no network dependency at runtime. Built by
# pipeline/07_prepare_deploy.py (Tier D dropped, intermediates removed,
# host list pre-aggregated) -- 1043 MB -> 102 MB.
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ core/
COPY app/ app/
COPY prompts/ prompts/
COPY data/out/perimeter-deploy.duckdb data/out/perimeter-deploy.duckdb

ENV PERIMETER_DB=/app/data/out/perimeter-deploy.duckdb \
    PYTHONUNBUFFERED=1 \
    PERIMETER_LLM_DISABLED=1

# Render supplies $PORT. One worker: DuckDB takes a process-level lock, so a
# second worker would fail to open the file.
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
