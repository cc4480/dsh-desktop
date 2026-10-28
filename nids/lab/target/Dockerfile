FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nginx-light dnsmasq netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY nginx.conf /etc/nginx/nginx.conf
COPY dnsmasq.conf /etc/dnsmasq.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
