# Zeek sensor for the lab: the official LTS image plus JA4 TLS fingerprinting.
#
#   zeek/foxio/ja4  compiled plugin, actively maintained by FoxIO; writes `ja4` (and the
#                   JA4+ fields) to ssl.log. JA4 sorts TLS extensions before hashing, so it
#                   is stable across Chrome's per-connection extension-order randomisation.
#
# JA3 (zeek/salesforce/ja3) is deliberately not installed: its repository was archived in
# May 2025, and JA3 changes per connection for Chrome.
#
# Licensing: the JA4 client fingerprint is BSD-3. The package also emits JA4+
# fields (ja4s, ja4h, ja4x, ...) under the FoxIO License 1.1: free for academic and
# internal use, but monetising them needs an OEM licence from FoxIO.
# Pinned to an exact Zeek release, not the floating `lts` tag: the JA4 plugin is compiled
# against Zeek's headers, so a silent major-version jump could break the build.
# 9.0 is the current long-term-support line (released 2026-09-17, about a year of fixes).
# JA4's own CI tests Zeek 8.0; a read of its source found nothing Zeek 9.0 removed. If the
# plugin fails to build or load on 9.0, use the previous LTS (supported until Zeek 9.1):
#   docker build --build-arg ZEEK_IMAGE=zeek/zeek:8.0.11 lab/sensor
ARG ZEEK_IMAGE=zeek/zeek:9.0.1
FROM ${ZEEK_IMAGE}

# Pinned to the commit this project was checked against.
ARG JA4_COMMIT=c6469a7b0dbf8fe963810162429fbfd9d1acc4d5

# The JA4 plugin is C++ built against this Zeek; the toolchain is removed afterwards.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake make g++ git libpcap-dev libssl-dev ca-certificates \
 && zkg autoconfig --force \
 && zkg install --force --skiptests zeek/foxio/ja4 --version "${JA4_COMMIT}" \
 && apt-get purge -y cmake make g++ && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Load the packages, Community IDs (built into Zeek >= 6) and the detectors the rules
# rely on, whatever the image's default local.zeek happens to contain.
RUN printf '%s\n' \
      '@load packages' \
      '@load policy/protocols/conn/community-id-logging' \
      '@load protocols/ssh/detect-bruteforcing' \
      '@load misc/capture-loss' \
      '@load misc/stats' \
    >> "$(zeek-config --site_dir)/local.zeek" \
 && zeek -N | grep -i ja4 \
 && zeek local -e 'event zeek_init() { print "sensor scripts load OK"; }'
