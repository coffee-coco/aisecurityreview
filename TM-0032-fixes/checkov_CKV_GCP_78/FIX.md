### Vulnerability Analysis
Checkov rule `CKV_GCP_78` checks whether Google Cloud Storage (GCS) buckets have object versioning enabled. In `terraform/gcp/gcs.tf`, the `google_storage_bucket.terragoat_website` resource definition omitted the `versioning` block. Without versioning, any accidental or malicious object overwrite or deletion immediately destroys the prior state of the object permanently, violating recovery and audit controls (NIST AU-2, AU-12, CP-9).

### Remediation
A `versioning` configuration block was added to the `google_storage_bucket.terragoat_website` resource in `terraform/gcp/gcs.tf`:
```hcl
  versioning {
    enabled = true
  }
```
Enabling object versioning preserves past versions of objects whenever they are modified or deleted, allowing recovery from accidental loss or ransomware attacks.

### Verification
The included test (`test_gcs_versioning.py`) inspects `terraform/gcp/gcs.tf` and verifies that `google_storage_bucket.terragoat_website` contains a `versioning` block with `enabled = true`. You can run this test using `pytest test_gcs_versioning.py` or validate with Checkov (`checkov -f terraform/gcp/gcs.tf --check CKV_GCP_78`).