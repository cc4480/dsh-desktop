### Brute force (T1110)
1. Check the target's auth log for the source: failed vs successful logins, and which accounts.
2. **Any success after many failures is a compromise**: disable the account, rotate credentials, review that session.
3. Block the source; confirm key-only auth / MFA / lockout policy on the service.
4. If the source is internal, treat it as a possibly compromised host.
