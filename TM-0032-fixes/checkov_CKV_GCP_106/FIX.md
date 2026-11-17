### Vulnerability Details
Checkov rule `CKV_GCP_106` checks that Google Compute Engine ingress firewall rules do not allow unrestricted (`0.0.0.0/0` or `::/0`) inbound access to unencrypted HTTP port 80. Allowing unrestricted HTTP port 80 ingress violates NIST controls AC-4 (Information Flow Enforcement) and SC-7 (Boundary Protection).

### Why It Is Exploitable
In `terraform/gcp/networks.tf` (lines 19-27):
```hcl
resource "google_compute_firewall" "allow_all" {
  name          = "terragoat-${var.environment}-firewall"
  network       = google_compute_network.vpc.id
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
}
```
`source_ranges` was set to `["0.0.0.0/0"]` while `ports` was set to `["0-65535"]`. Because `0-65535` covers port 80, the firewall allows unrestricted plaintext HTTP traffic from the entire internet to all instances attached to the VPC.

### Fix Details
The fix updates `source_ranges` on `google_compute_firewall.allow_all` from `["0.0.0.0/0"]` to `["10.0.0.0/24"]` (the VPC subnet CIDR defined in `public-subnetwork`). This restricts ingress to instances within the internal subnet and eliminates unrestricted internet exposure on port 80, satisfying `CKV_GCP_106`.

### Verification
- Run `pytest test_networks_firewall_http.py` to verify the firewall configuration no longer permits unrestricted access to port 80.
- Alternatively, run `checkov -f terraform/gcp/networks.tf --check CKV_GCP_106`.