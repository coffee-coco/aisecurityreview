### Vulnerability
The `google_compute_disk` resource named `unencrypted_disk` did not specify an encryption key block, failing Checkov check `CKV_GCP_37` ("Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK)"). Without customer-supplied encryption keys (CSEK) or customer-managed keys (CMEK), disks rely solely on default Google-managed keys. In regulated or high-security environments, customer control over the cryptographic lifecycle (such as instant cryptographic erasure by withholding or rotating the raw key) is required to ensure data protection compliance (e.g., NIST SC-13, SC-28).

### Remediation
A `disk_encryption_key` block with `raw_key` was added to `google_compute_disk.unencrypted_disk` in `terraform/gcp/instances.tf`. This provides a customer-supplied 256-bit AES key (RFC 4648 base64-encoded) for the disk's encryption, satisfying Checkov policy `CKV_GCP_37`.

### Verification
Run `pytest test_instances_csek.py` from the repository root (or with `REPO_ROOT` set) to verify that `google_compute_disk.unencrypted_disk` contains the required `disk_encryption_key` configuration with `raw_key`.