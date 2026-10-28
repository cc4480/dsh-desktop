# Debian 13 (current stable). Debian 12 left regular security support in June 2026; if a
# package is missing on 13, build with --build-arg DEBIAN_TAG=bookworm-slim.
ARG DEBIAN_TAG=trixie-slim
FROM debian:${DEBIAN_TAG}
RUN apt-get update && apt-get install -y --no-install-recommends \
        hping3 nmap curl bind9-dnsutils netcat-openbsd coreutils iproute2 sshpass openssh-client tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY *.sh /scripts/
RUN chmod +x /scripts/*.sh
