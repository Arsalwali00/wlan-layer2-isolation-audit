# Suricata NIDS Evaluation Configuration

To reproduce the rate-based anomaly detection results reported in Section 4.3 and Table 1 of the research paper:

1. Copy `local.rules` to your Suricata rules directory:
   ```bash
   sudo cp local.rules /etc/suricata/rules/local.rules
   ```

2. Ensure `suricata.yaml` includes `local.rules` in its `rule-files` list and enables Layer-2 decoding:
   ```yaml
   rule-files:
     - local.rules
   ```

3. Run Suricata on the monitoring interface (e.g., `eth0` or `wlan0`):
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   ```

4. Monitor alerts in `/var/log/suricata/fast.log`:
   ```bash
   tail -f /var/log/suricata/fast.log | grep "1000001"
   ```
