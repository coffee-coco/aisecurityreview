### Vulnerability Explanation
Checkov rule `CKV_AWS_327` ("Ensure RDS Clusters are encrypted using KMS CMKs") checks that `aws_rds_cluster` resources specify customer-managed KMS keys via the `kms_key_id` attribute rather than defaulting to AWS-managed keys or unencrypted storage. Using a Customer Managed Key (CMK) ensures organization-specific key rotation policies, granular access control, and auditing via AWS CloudTrail.

In `terraform/aws/rds.tf`, all nine `aws_rds_cluster` resources (`app1-rds-cluster` through `app9-rds-cluster`, lines 1-144) lacked both the `kms_key_id` and `storage_encrypted` attributes, violating compliance policies requiring KMS CMK encryption at rest.

### Fix Details
1. Added an `aws_kms_key.rds_key` resource to `terraform/aws/rds.tf` with key rotation enabled (`enable_key_rotation = true`) and a standard deletion window.
2. In each of the nine `aws_rds_cluster` resources (`app1-rds-cluster` through `app9-rds-cluster`), added:
   - `storage_encrypted = true`
   - `kms_key_id = aws_kms_key.rds_key.arn`

### Verification
- Run the provided unit test with `pytest test_rds_cluster_kms_encryption.py` or `python -m unittest test_rds_cluster_kms_encryption.py`. The test checks that all 9 clusters configure `kms_key_id` and `storage_encrypted = true`, and that a KMS key resource is defined.
- Alternatively, run Checkov directly: `checkov -f terraform/aws/rds.tf --check CKV_AWS_327` to confirm all 9 resources pass.