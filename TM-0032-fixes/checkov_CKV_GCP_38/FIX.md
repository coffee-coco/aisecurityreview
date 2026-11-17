### Vulnerability Details
Checkov rule `CKV_GCP_38` failed for `google_compute_instance.server`. By default, Google Cloud encrypts Compute Engine disks with Google-managed encryption keys. However, for sensitive and critical workloads complying with strict data governance mandates (such as NIST SC-13 and SC-28), disks must be encrypted with Customer Supplied Encryption Keys (CSEK). Without CSEK, the customer lacks exclusive cryptographic control over disk encryption keys at rest.

### Evidence
In `terraform/gcp/instances.tf` line 3 (`google_compute_instance.server`):
```hcl
boot_disk {
  initialize_params {
    image = "debian-cloud/debian-9"
  }
  auto_delete = true
}
```
The `boot_disk` block does not specify `disk_encryption_key_raw`.

### Fix
In `terraform/gcp/instances.tf`, `disk_encryption_key_raw` was added to `boot_disk` of `google_compute_instance.server`. This configures a 256-bit customer-supplied encryption key (encoded in RFC 4648 base64) to encrypt the instance boot disk, satisfying Checkov check `CKV_GCP_38`.

### Verification
Run the test suite using `pytest test_csek_encryption.py` or `python -m unittest test_csek_encryption.py`. Alternatively, run Checkov against `terraform/gcp/instances.tf` (`checkov -f terraform/gcp/instances.tf --check CKV_GCP_38`) to confirm that `CKV_GCP_38` passes.