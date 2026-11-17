### Vulnerability Explanation
Checkov rule `CKV_AWS_280` requires that Amazon Neptune cluster snapshots are encrypted using a Customer Managed Key (CMK) in AWS KMS. When snapshots are unencrypted or encrypted using the default AWS-managed key, organizations lack direct control over key rotation, cryptographic access policies, and audit logging for snapshot access.

### Evidence
In `terraform/aws/neptune.tf` at line 41:
```terraform
resource "aws_neptune_cluster_snapshot" "default" {
  db_cluster_identifier          = aws_neptune_cluster.default.id
  db_cluster_snapshot_identifier = "resourcetestsnapshot1"
}
```
The `aws_neptune_cluster_snapshot.default` resource did not specify `kms_key_id`, leaving the snapshot without customer-managed KMS encryption.

### Remediation
Added the `kms_key_id` argument to `aws_neptune_cluster_snapshot.default` referencing a customer-managed KMS key ARN (`"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"`). This ensures Neptune cluster snapshots are encrypted at rest with a CMK.

### Verification
- Run the provided unit test: `pytest test_neptune_snapshot_cmk.py`
- Alternatively run Checkov: `checkov -f terraform/aws/neptune.tf --check CKV_AWS_280`