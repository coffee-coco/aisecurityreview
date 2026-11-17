### Vulnerability Description
Checkov rule `CKV_GCP_88` checks that Google Compute Engine firewall rules do not allow unrestricted ingress access to MySQL (TCP port 3306) from any IP (`0.0.0.0/0`). Unrestricted access to database ports allows external attackers on the internet to attempt brute-force authentication, exploit database server vulnerabilities, or access sensitive data directly.

### Why It Was Exploitable
In `terraform/gcp/networks.tf`, the firewall resource `google_compute_firewall.allow_all` configured:
- `source_ranges = ["0.0.0.0/0"]` (open to the entire internet)
- `ports = ["0-65535"]` (all TCP ports, which includes MySQL port 3306)

Because port 3306 fell within the unrestricted `0-65535` range with an internet-wide CIDR, anyone on the public internet could reach MySQL listening on any instance attached to this VPC.

### Remediation
In `terraform/gcp/networks.tf`, `source_ranges` was changed from `["0.0.0.0/0"]` to `["10.0.0.0/24"]`, matching the VPC public subnetwork CIDR block. This ensures that ingress across the port range is restricted to internal network traffic rather than being exposed publicly to the internet.

### Verification
Run `pytest test_networks_firewall.py`. The test parses `google_compute_firewall.allow_all` from `terraform/gcp/networks.tf` and checks whether port 3306 is exposed to `0.0.0.0/0`. It fails on the original code and passes after updating `source_ranges`.