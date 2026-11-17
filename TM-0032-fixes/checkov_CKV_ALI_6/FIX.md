### Vulnerability Analysis
Checkov rule `CKV_ALI_6` requires Alibaba Cloud Object Storage Service (OSS) buckets to have server-side encryption enabled using a Customer Master Key (CMK) managed via Key Management Service (KMS). Without server-side encryption configured with a KMS CMK, data at rest is not protected by customer-controlled cryptographic keys, increasing the risk of data exposure and non-compliance with data protection standards (NIST SC-13, SC-28).

In the evidence:
1. `terraform/alicloud/bucket.tf`: `alicloud_oss_bucket.bad_bucket` did not define a `server_side_encryption_rule` block.
2. `terraform/alicloud/trail.tf`: `alicloud_oss_bucket.trail` did not define a `server_side_encryption_rule` block.

### Remediations
For both `alicloud_oss_bucket.bad_bucket` in `terraform/alicloud/bucket.tf` and `alicloud_oss_bucket.trail` in `terraform/alicloud/trail.tf`, a `server_side_encryption_rule` block was added specifying `sse_algorithm = "KMS"` and configuring `kms_master_key_id`.

### Verification
The included test (`test_oss_bucket_encryption.py`) parses the Terraform resources from disk and verifies that each `alicloud_oss_bucket` resource defines a `server_side_encryption_rule` with `kms_master_key_id`.