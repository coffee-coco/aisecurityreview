### Vulnerability Details
Checkov rule `CKV_GCP_3` requires that Google Cloud Compute firewall ingress rules do not allow unrestricted Remote Desktop Protocol (RDP, port 3389) access from the public internet (`0.0.0.0/0` or `::/0`). In `terraform/gcp/networks.tf`, the firewall resource `google_compute_firewall.allow_all` configures `source_ranges = ["0.0.0.0/0"]` with allowed TCP ports `["0-65535"]`. Because `0-65535` covers port 3389, RDP is exposed to the entire internet without restriction, allowing attackers to conduct port scanning, brute-force attacks, and attempt remote exploitation.

### Fix
Updated `source_ranges` on `google_compute_firewall.allow_all` from `["0.0.0.0/0"]` to the internal subnetwork range `["10.0.0.0/24"]` (matching `google_compute_subnetwork.public-subnetwork`). This restricts the allowed traffic to internal VPC communication rather than exposing all ports, including RDP, to the public internet.

### Verification
Run the test with `pytest test_networks_firewall_rdp.py` or execute Checkov against the file: `checkov -f terraform/gcp/networks.tf --check CKV_GCP_3`.