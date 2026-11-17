### Vulnerability Details
Checkov rule `CKV_AWS_347` checks whether Amazon Neptune clusters are encrypted at rest using a customer-managed KMS key (CMK). In `terraform/aws/neptune.tf`, `aws_neptune_cluster.default` had `storage_encrypted = false` and omitted `kms_key_arn`. Without encryption with a customer-managed key, data at rest in the graph database lacks granular access control, auditability, and key rotation capabilities provided by AWS KMS CMKs.

### Remediation
1. Created an `aws_kms_key` resource (`aws_kms_key.neptune`) with key rotation enabled.
2. In `aws_neptune_cluster.default`, updated `storage_encrypted = true` and configured `kms_key_arn = aws_kms_key.neptune.arn` to encrypt the Neptune cluster with the customer-managed KMS key.

### Verification
Run the test via `pytest test_neptune_kms_encryption.py` or run `checkov -f terraform/aws/neptune.tf -c CKV_AWS_347` to confirm that the check passes.