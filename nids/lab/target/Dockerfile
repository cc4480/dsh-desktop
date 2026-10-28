# Debian 13 (current stable). Debian 12 left regular security support in June 2026; if a
# package is missing on 13, build with --build-arg DEBIAN_TAG=bookworm-slim.
ARG DEBIAN_TAG=trixie-slim
FROM debian:${DEBIAN_TAG}
RUN apt-get update && apt-get install -y --no-install-recommends nginx dnsmasq netcat-openbsd \
        openssh-server openssl \
    && rm -rf /var/lib/apt/lists/*
# Self-signed certificate: the implant's HTTPS beacon presents it (SELF_SIGNED_TLS_REPEATED).
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=web-lab-01" \
        -keyout /etc/ssl/private/lab.key -out /etc/ssl/certs/lab.crt
# A login for the brute-force scenario; the attacker never learns this password.
RUN useradd -m lab && echo "lab:$(openssl rand -hex 16)" | chpasswd && mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY nginx.conf /etc/nginx/nginx.conf
COPY dnsmasq.conf /etc/dnsmasq.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
