#!/bin/sh
set -e
dnsmasq --keep-in-foreground &
( while true; do nc -lk 9000 >/dev/null; sleep 1; done ) &   # bulk-upload sink
exec nginx -g 'daemon off;'
