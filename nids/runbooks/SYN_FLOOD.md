### SYN flood (T1498.001)
1. Confirm on the target: `ss -s` shows a large `synrecv` count; service latency is up.
2. Confirm SYN cookies are on: `sysctl net.ipv4.tcp_syncookies` (should be 1).
3. If the source is a single host, block it (policy-engine command). If spoofed / distributed, rate-limit the port upstream instead and escalate to the network provider.
4. Keep the incident pcap (`enable_verbose_logging`) for the post-incident review.
5. Remove the block after the attack window and record the rollback in the ticket.
