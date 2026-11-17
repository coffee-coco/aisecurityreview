### Vulnerability Details
Checkov rule `CKV_GCP_62` checks that Google Cloud Storage (GCS) buckets have access logging enabled. In `terraform/gcp/gcs.tf`, `google_storage_bucket.terragoat_website` does not define a `logging` block specifying a destination `log_bucket`.

Without access logging, storage operations (such as read, write, and delete events) are not recorded to an audit trail bucket. This prevents security teams from detecting unauthorized access, investigating security breaches, and meeting compliance requirements (such as NIST AU-2, AU-3, AU-12).

### Fix Details
A `logging` block has been added to `google_storage_bucket.terragoat_website` pointing `log_bucket` to `"terragot-${var.environment}-logs"`.

### Verification
Run the test via `pytest test_gcs_logging.py` or `python -m unittest test_gcs_logging.py`. The test will parse `terraform/gcp/gcs.tf` and ensure that `google_storage_bucket.terragoat_website` has a `logging` block configured with `log_bucket`.