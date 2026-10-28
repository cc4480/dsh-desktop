### Repeated self-signed TLS (T1573)
1. Is the destination a known internal service that legitimately uses a self-signed certificate?
2. Check for BEACONING or other incidents from the same host (campaign view): together they suggest encrypted C2.
3. On the sensor, inspect the certificate subject/issuer in x509.log and the SNI in ssl.log.
