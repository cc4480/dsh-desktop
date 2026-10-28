### Port scan (T1046)
1. Identify the source host owner. Is it an approved scanner that is missing from `known_scanners`?
2. If internal and unapproved: treat as a possibly compromised host; check its recent logins and processes.
3. Check whether any probed port answered (`conn_state=SF` from the same source): those services are now known to the attacker.
4. Block or isolate the source; verify the target's exposed services are expected.
