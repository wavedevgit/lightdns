# LightDNS Product

LightDNS is a lightweight DNS blocker, encrypted forwarding relay, and local DNS record manager for home networks and small infrastructure deployments.

Its operator needs one binary that starts without external services, handles high query volume, accepts familiar Pi-hole-style lists, and remains understandable without specialist DNS tooling. YAML provides reproducible bootstrap configuration; the authenticated dashboard manages live settings and persists them back to a writable YAML state file.

Core responsibilities are local authoritative answers, filtering, cached forwarding, encrypted DNS transport, DNSSEC-aware forwarding, health reporting, and safe configuration changes. The product stays stateless apart from one optional YAML state file so replicas remain easy to deploy and replace.
