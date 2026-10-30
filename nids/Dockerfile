# Production image: no demo data, no pre-built models. Mount your own.
FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN useradd -m -u 10001 nids && mkdir -p /app/data /app/models && chown -R nids /app/data /app/models
USER nids
VOLUME ["/app/data", "/app/models"]
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3).status != 200)"
# Detector: docker run -v nids-data:/app/data -v nids-models:/app/models -v /var/log/zeek/current:/zeek:ro nids \
#              python -m nids watch /zeek --db /app/data/nids.db
# Dashboard: bind 0.0.0.0 inside the container and publish to localhost only, or put it behind a TLS proxy:
#   docker run -e NIDS_USERS=/app/data/users.yaml -p 127.0.0.1:8501:8501 -v nids-data:/app/data nids
CMD ["streamlit", "run", "dashboard/app.py", "--server.address", "0.0.0.0"]
