### Vulnerability Details
In AWS RDS / Aurora, encryption at rest protects automated backups, read replicas, and underlying database storage using keys managed via AWS KMS. In Terraform's `aws_rds_cluster` resource, the `storage_encrypted` attribute defaults to `false`. Without explicitly specifying `storage_encrypted = true`, Aurora clusters and their underlying storage volumes are created unencrypted at rest, violating NIST SC-13 and SC-28 controls and triggering Checkov policy `CKV_AWS_96`.

### Remediation
Each `aws_rds_cluster` resource (`app1-rds-cluster` through `app9-rds-cluster`) in `terraform/aws/rds.tf` has been updated to include `storage_encrypted = true`. This ensures that Aurora clusters provisioned using this configuration encrypt data at rest using the default AWS KMS key (or a customer-managed KMS key if specified).

### Verification
The unit test in `test_rds_encryption.py` inspects `terraform/aws/rds.tf` to verify that every `aws_rds_cluster` block explicitly sets `storage_encrypted = true`. It fails against the original unencrypted configuration and passes after the remediation.