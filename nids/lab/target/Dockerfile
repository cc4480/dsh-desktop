FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nginx-light dnsmasq netcat-openbsd \
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
