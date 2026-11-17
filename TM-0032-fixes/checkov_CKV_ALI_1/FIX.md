### Vulnerability Explanation
Checkov check `CKV_ALI_1` identifies Alibaba Cloud Object Storage Service (OSS) buckets configured with public access. In `terraform/alicloud/bucket.tf`, the resource `alicloud_oss_bucket.bad_bucket` configured `acl = "public-read-write"`. This configuration grants anonymous public read and write permissions to the bucket, allowing unauthenticated third parties to view, download, overwrite, or upload arbitrary objects, leading to data exfiltration and potential data tampering.

### Remediation
The `acl` parameter in `alicloud_oss_bucket.bad_bucket` was changed from `"public-read-write"` to `"private"`. This ensures that access to the bucket and its objects requires authenticated credentials with appropriate RAM policies.

### Verification
Run the test with `pytest test_bucket_acl.py` or run Checkov against the Terraform directory (`checkov -f terraform/alicloud/bucket.tf -c CKV_ALI_1`) to verify that the bucket configuration is now compliant.