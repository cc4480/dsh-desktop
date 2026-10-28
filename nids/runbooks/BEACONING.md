### C2 beaconing (T1071)
1. Rule out known periodic software (update agents, NTP, monitoring) for the destination.
2. Check the destination's reputation and the TLS fingerprint (ssl.log JA3/JA4) on the sensor.
3. If unexplained, isolate the host and collect process / network-connection state.
4. Search for other hosts contacting the same destination.
