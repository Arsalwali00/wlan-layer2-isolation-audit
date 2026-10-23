# Zeek Configuration: Default Sensor Profile vs. Stateful Layer-2 Inspection
# Author: Arslan Wali
# Reference: An Empirical Study on Layer-2 Station Isolation Deficits (2026)

# NOTE: In default Zeek installations (local.zeek), ARP protocol parsing is disabled.
# To activate stateful ARP conflict detection (Notice: ARP::Duplicate_IP_MAC),
# uncomment the following line:

# @load policy/protocols/arp.zeek

# When loaded, Zeek's in-memory ARP table evaluates each ingress frame:
# it triggers immediately on the first conflicting IP-MAC mapping (state-based).
