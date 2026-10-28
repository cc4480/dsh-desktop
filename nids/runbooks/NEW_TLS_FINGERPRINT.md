### Unseen TLS client fingerprint (T1071.001)
1. Identify the process on the source host making the connection (EDR / `ss -tp`).
2. New legitimate software produces new fingerprints too: confirm with the host owner.
3. If unexplained, capture traffic and check the destination's reputation.
