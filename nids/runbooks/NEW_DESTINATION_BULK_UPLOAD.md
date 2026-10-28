### Bulk upload to a new destination (T1048)
1. Who owns the destination? Is it a sanctioned backup, CI artefact store or cloud service?
2. Ask the host owner whether a large transfer was expected (release, backup, migration).
3. If not: isolate the host, preserve it, and estimate what data could have left.
4. If expected and recurring: rebuild the profile so the destination becomes known.
