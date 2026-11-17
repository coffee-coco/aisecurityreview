### Vulnerability Details
Checkov rule `CKV_AWS_279` checks that Neptune cluster snapshots are securely encrypted at rest. When `aws_neptune_cluster_snapshot` is defined without encryption enabled, snapshots can be stored unencrypted at rest, potentially exposing sensitive graph database data to unauthorized access if snapshot storage is breached or improperly shared.

### Remediation
In `terraform/aws/neptune.tf`, `storage_encrypted = true` was added to `aws_neptune_cluster_snapshot.default`. This ensures that the snapshot is configured for storage encryption, satisfying `CKV_AWS_279`.

### Verification
The unit test reads `terraform/aws/neptune.tf` and asserts that `storage_encrypted = true` is explicitly configured in `aws_neptune_cluster_snapshot.default`. It fails against the original unencrypted configuration and passes after the fix is applied.