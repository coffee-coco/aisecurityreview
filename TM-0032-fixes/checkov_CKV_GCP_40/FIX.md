### Vulnerability Details
Checkov rule `CKV_GCP_40` checks that Google Compute Engine instances do not have external (public) IP addresses assigned. In Google Cloud Terraform, defining an `access_config` block inside a `network_interface` block (even an empty block `access_config {}`) assigns an ephemeral public IP address to the instance.

### Exploitation & Impact
In `terraform/gcp/instances.tf`, `google_compute_instance.server` has `access_config {}` under `network_interface` (line 15). This exposes the compute instance directly to the public internet, increasing the attack surface by subjecting it to unauthorized external access, scanning, and brute-force attempts.

### Fix
Removed the `access_config {}` block from `network_interface` within `google_compute_instance.server`. Without an `access_config` block, the instance only receives a private internal IP address within its VPC subnetwork.

### Verification
Run the included unit test (`pytest test_instances_no_public_ip.py` or `python -m unittest test_instances_no_public_ip.py`), or run `checkov -f terraform/gcp/instances.tf --check CKV_GCP_40` to confirm that the check passes.