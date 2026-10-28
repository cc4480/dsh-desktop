### Unclassified anomaly
No signature matched. The flows are more anomalous than the stated percentile of baseline traffic.
1. Look at what makes them unusual (bytes, duration, failed states) in the raw evidence.
2. Ask the asset owner whether the activity is expected (backups, releases, migrations).
3. If not expected, capture traffic (`enable_verbose_logging`) and escalate.
4. If it is expected and recurring, add it to the baseline and retrain, or write a rule.
