# LightDNS Product

LightDNS is a lightweight DNS blocker, encrypted forwarding relay, and local DNS record manager for home networks and small infrastructure deployments.

Its operator needs one binary that starts without external services, handles high query volume, accepts familiar Pi-hole-style lists, and remains understandable without specialist DNS tooling. YAML provides reproducible bootstrap configuration; SQLite stores live settings, users, sessions, managed zones, records, and audit history.

Core responsibilities are authoritative zone answers, filtering, cached forwarding, encrypted DNS transport, DNSSEC-aware forwarding, health reporting, role-aware management APIs, and safe configuration changes. DNS requests use immutable in-memory snapshots while SQLite remains off the query hot path.
