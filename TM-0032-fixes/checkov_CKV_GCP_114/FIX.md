### Vulnerability Details
Checkov rule `CKV_GCP_114` flagged `google_storage_bucket.terragoat_website` for not enforcing Cloud Storage Public Access Prevention. Without `public_access_prevention = "enforced"`, Cloud Storage buckets default to `inherited`, allowing IAM policies or ACLs (such as the `allUsers` role binding defined on line 17) to expose bucket contents publicly to the internet.

### Fix Details
In `terraform/gcp/gcs.tf`, `public_access_prevention = "enforced"` was added to `resource "google_storage_bucket" "terragoat_website"`. This setting activates GCP's Public Access Prevention mechanism at the bucket level, overriding public ACLs and IAM grants to ensure no objects in the bucket can be publicly read.

### Verification
Run the test via `pytest test_gcs_public_access_prevention.py` or run Checkov (`checkov -f terraform/gcp/gcs.tf --check CKV_GCP_114`), confirming that the check passes.