### Web wordlist scan (T1595.003)
1. Look for any requested path that returned 200/401/403 rather than 404: those are what the scanner found.
2. Make sure nothing sensitive is exposed at those paths (admin panels, backups, `.git`, `.env`).
3. Block or rate-limit the source at the edge / WAF.
