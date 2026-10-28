### DNS tunnelling (T1048)
1. Pull the queried parent domain from dns.log for the source host (on the sensor, not via the dashboard).
2. Check whether the parent domain is new, recently registered, or on threat-intel lists.
3. Isolate the host; preserve memory and disk before reimaging.
4. Sinkhole or block the parent domain at the resolver.
5. Estimate the data volume from query count × mean label length.
