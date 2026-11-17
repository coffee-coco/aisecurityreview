### Vulnerability Explanation
Checkov rule `CKV_GCP_28` flags Google Cloud Storage buckets configured to allow anonymous or public access. In `terraform/gcp/gcs.tf`, lines 17–21 define a `google_storage_bucket_iam_binding` resource named `allow_public_read` that assigns the `roles/storage.objectViewer` role to `"allUsers"`. The `allUsers` principal represents anyone on the internet, granting unauthenticated read access to all objects stored within the bucket. This exposes potentially sensitive data to unintended disclosure and exfiltration.

### Fix Details
Removed the `google_storage_bucket_iam_binding.allow_public_read` resource completely from `terraform/gcp/gcs.tf`. Without this IAM binding, the bucket adheres to the principle of least privilege, ensuring that only explicitly authorized GCP identities can access the bucket objects.

### Verification
Run `pytest test_gcs_public_access.py` to confirm that `allUsers`, `allAuthenticatedUsers`, and the public IAM binding are no longer present in `terraform/gcp/gcs.tf`. Alternatively, running Checkov (`checkov -f terraform/gcp/gcs.tf --check CKV_GCP_28`) will verify that the rule passes.