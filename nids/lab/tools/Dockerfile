FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        hping3 nmap curl dnsutils netcat-openbsd coreutils iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY *.sh /scripts/
RUN chmod +x /scripts/*.sh
