### Vulnerability scanner (T1595.002)
1. Is this an approved scan? If so, add the source to `known_scanners` in the asset registry.
2. If not: block the source and check the web server's logs for requests that did not fail.
3. Prioritise patching anything the scanner targeted on this host.
