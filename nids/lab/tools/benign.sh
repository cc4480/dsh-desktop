#!/bin/bash
# Always-on benign traffic: page loads, DNS lookups, the odd connection to a closed port.
. /scripts/lib.sh
names=(www.example.lab api.example.lab cdn.example.lab mail.example.lab login.example.lab)
paths=(/ /index.html /api/status /static/app.js /img/logo.png)
n=0
while true; do
  dig +short +tries=1 +time=1 @"$TARGET" "${names[RANDOM % ${#names[@]}]}" >/dev/null || true
  curl -s -o /dev/null --max-time 2 "http://$TARGET${paths[RANDOM % ${#paths[@]}]}" || true
  n=$((n + 1))
  if (( n % 60 == 0 )); then curl -s -o /dev/null --max-time 1 "http://$TARGET:81/" || true; fi
  sleep "0.$((RANDOM % 5 + 1))"
done
