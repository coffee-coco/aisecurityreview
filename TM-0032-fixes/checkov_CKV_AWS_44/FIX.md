### Vulnerability Details
Checkov check `CKV_AWS_44` flags Amazon Neptune clusters that do not have storage encryption enabled at rest. When data stored in Neptune is unencrypted, database files, backups, and cluster snapshots residing on the underlying storage media could be exposed if physical media or unauthorized disk access occurs.

### Root Cause in Code
In `terraform/aws/neptune.tf`, `aws_neptune_cluster.default` explicitly disabled storage encryption:
```terraform
  storage_encrypted                   = false
```

### Fix Details
Updated `storage_encrypted` to `true` in `terraform/aws/neptune.tf` for `aws_neptune_cluster.default`. This ensures AWS Neptune encrypts the underlying storage volume (along with automated backups and snapshots) using AWS KMS at rest.

### Verification
Run the test suite using `pytest test_neptune_storage_encryption.py`. It reads `terraform/aws/neptune.tf` and verifies that `storage_encrypted` is set to `true` within the `aws_neptune_cluster` resource block. Alternatively, run `checkov -f terraform/aws/neptune.tf --check CKV_AWS_44` to verify the rule passes.