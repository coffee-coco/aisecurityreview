### Vulnerability Details
Checkov rule `CKV_OCI_10` verifies that Oracle Cloud Infrastructure (OCI) Object Storage buckets are not configured with public access. In `terraform/oracle/bucket.tf`, the resource `oci_objectstorage_bucket.secretsquirrel` had `access_type = "ObjectRead"`. This setting allows anonymous public read access to objects stored in the bucket without requiring authentication or authorization.

### Remediation
The `access_type` attribute of `oci_objectstorage_bucket.secretsquirrel` was changed from `"ObjectRead"` to `"NoPublicAccess"`. This ensures the bucket is private and objects can only be accessed by authenticated and authorized principals.

### Verification
The unit test reads `terraform/oracle/bucket.tf` and checks the `access_type` parameter of the `oci_objectstorage_bucket.secretsquirrel` block, verifying that it is set to `"NoPublicAccess"` and not any public setting such as `"ObjectRead"` or `"ObjectReadWithoutList"`. Running `pytest test_bucket_public_access.py` or running Checkov (`checkov -f terraform/oracle/bucket.tf --check CKV_OCI_10`) confirms the fix.