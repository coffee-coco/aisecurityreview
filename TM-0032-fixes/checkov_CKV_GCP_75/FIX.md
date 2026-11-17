### Vulnerability Explanation
Checkov rule `CKV_GCP_75` checks that Google Cloud VPC firewall ingress rules do not allow unrestricted access to FTP (port 21) from any source IP (`0.0.0.0/0`). FTP transmits data and credentials in plaintext, making services listening on this port vulnerable to eavesdropping, credential theft, and unauthorized access when exposed to the public internet.

### Evidence
In `terraform/gcp/networks.tf` lines 19-27:
```terraform
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
The firewall rule specifies `source_ranges = ["0.0.0.0/0"]` and allows all TCP ports `0-65535`, which includes FTP port 21, thus granting unrestricted ingress FTP access to any instance in the network.

### Remediation
The `source_ranges` parameter in `google_compute_firewall.allow_all` was updated from `["0.0.0.0/0"]` to `["10.0.0.0/24"]`, matching the internal CIDR range of `google_compute_subnetwork.public-subnetwork`. Restricting inbound traffic to the internal network range prevents external internet access to port 21 and satisfies Checkov rule `CKV_GCP_75`.

### Verification
Run the provided test with `pytest test_firewall_ftp.py` or run `checkov -f terraform/gcp/networks.tf --check CKV_GCP_75`. The test verifies that port 21 is not exposed to `0.0.0.0/0` or `::/0`.