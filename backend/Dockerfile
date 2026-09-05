FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN addgroup --system socwerk && adduser --system --ingroup socwerk socwerk
WORKDIR /app

COPY backend /app/backend
RUN pip install /app/backend
COPY scenarios /app/scenarios

RUN mkdir -p /data && chown -R socwerk:socwerk /data
USER socwerk

ENV SOCWERK_DATA_DIR=/app/scenarios \
    SOCWERK_DATABASE_PATH=/data/socwerk.db \
    SOCWERK_ALLOWED_ORIGINS=http://localhost:5173

EXPOSE 8000
CMD ["uvicorn", "socwerk.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
