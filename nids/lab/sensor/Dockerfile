# Zeek sensor for the lab: the official LTS image plus the TLS fingerprinting packages.
#
#   JA4  (zeek/foxio/ja4)       compiled plugin; writes `ja4` (and JA4+ fields) to ssl.log.
#                               The rules use JA4: it is stable across Chrome's per-connection
#                               extension-order randomisation.
#   JA3  (zeek/salesforce/ja3)  scripts; writes `ja3`. Archived upstream (May 2025) and only a
#                               fallback here; build with --build-arg WITH_JA3=false if a
#                               future Zeek stops loading it. The JA4 package does not emit JA3.
#
# Licensing: the JA4 client fingerprint is BSD-3 like JA3. The package also emits JA4+
# fields (ja4s, ja4h, ja4x, ...) under the FoxIO License 1.1: free for academic and
# internal use, but monetising them needs an OEM licence from FoxIO.
ARG ZEEK_IMAGE=zeek/zeek:lts
FROM ${ZEEK_IMAGE}

# Pinned to the commits this project was checked against.
ARG JA4_COMMIT=c6469a7b0dbf8fe963810162429fbfd9d1acc4d5
ARG JA3_COMMIT=502cc6395811c54743b0561419d61900a6df3ff7
ARG WITH_JA3=true

# The JA4 plugin is C++ built against this Zeek; the toolchain is removed afterwards.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake make g++ git libpcap-dev libssl-dev ca-certificates \
 && zkg autoconfig --force \
 && zkg install --force --skiptests zeek/foxio/ja4 --version "${JA4_COMMIT}" \
 && if [ "${WITH_JA3}" = "true" ]; then \
      zkg install --force --skiptests zeek/salesforce/ja3 --version "${JA3_COMMIT}"; fi \
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
