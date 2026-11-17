### Vulnerability Details
In `terraform/aws/db-app.tf` line 22, the `aws_db_instance.default` resource configured `publicly_accessible = true`. When set to true, AWS RDS assigns a public IP address to the DB instance and makes it reachable from outside the VPC (depending on routing and security groups), violating Checkov check `CKV_AWS_17`. Database instances should generally reside in private subnets without public internet accessibility to mitigate unauthorized access and exposure to network-level attacks.

### Fix
Updated line 22 of `terraform/aws/db-app.tf` from `publicly_accessible = true` to `publicly_accessible = false`.

### Verification
Run `pytest test_rds_not_publicly_accessible.py` or run `checkov -f terraform/aws/db-app.tf --check CKV_AWS_17` to confirm the check passes.