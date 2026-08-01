FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN groupadd --system trustsoc && useradd --system --gid trustsoc --create-home --home-dir /app trustsoc
WORKDIR /app
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY . .
RUN mkdir -p /app/runtime && chown -R trustsoc:trustsoc /app
USER trustsoc
EXPOSE 8000
CMD ["uvicorn", "trustsoc.main:app", "--host", "0.0.0.0", "--port", "8000"]
