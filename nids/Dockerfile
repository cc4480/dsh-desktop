FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m nids && chown -R nids /app
USER nids
# Pre-build the demo so `docker run` is instant.
RUN python -m nids lab && python -m nids train data/lab/baseline && python -m nids run data/lab/demo --fresh \
    && python -m nids evaluate data/lab/demo
EXPOSE 8501
# Inside the container we must bind 0.0.0.0; publish it to localhost only:
#   docker run --rm -e NIDS_DASHBOARD_PASSWORD=... -p 127.0.0.1:8501:8501 nids
CMD ["streamlit", "run", "dashboard/app.py", "--server.address", "0.0.0.0"]
