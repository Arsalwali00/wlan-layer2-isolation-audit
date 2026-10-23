# Zeek NIDS Evaluation Configuration

To evaluate the operational discrepancy between default sensor profiles and stateful Layer-2 inspection reported in Section 4.3 and Section 5.2:

1. **Default Profile (Silent across all trials):**
   Run Zeek with standard site configuration (Layer-2 ARP disabled):
   ```bash
   sudo zeek -i eth0 local
   ```
   Inspect notices:
   ```bash
   cat notice.log
   # (Generates 0 alerts across all trials T-1 through T-5)
   ```

2. **Stateful Profile (Explicitly loaded):**
   Execute Zeek loading the stateful ARP policy:
   ```bash
   sudo zeek -i eth0 local policy/protocols/arp.zeek
   ```
   Inspect notices:
   ```bash
   cat notice.log | grep "ARP::Duplicate_IP_MAC"
   # (Fires on the first conflicting frame at t = Delta_t)
   ```
