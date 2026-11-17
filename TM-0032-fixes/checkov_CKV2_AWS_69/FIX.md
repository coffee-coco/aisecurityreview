### Vulnerability Details
Checkov rule `CKV2_AWS_69` validates that AWS RDS database instances are configured to enforce encryption in transit. For MySQL databases, TLS/SSL connection enforcement is controlled at the DB parameter group level via the `require_secure_transport` parameter. 

In `terraform/aws/db-app.tf`, `aws_db_instance.default` references `aws_db_parameter_group.default.name` (`parameter_group_name`). However, the `aws_db_parameter_group.default` resource (lines 65-95) did not configure `require_secure_transport`. Without this setting, MySQL permits unencrypted plaintext connections, exposing sensitive data and credentials to network sniffing and man-in-the-middle attacks.

### Fix Details
In `terraform/aws/db-app.tf`, added a parameter block to `aws_db_parameter_group.default`:
```hcl
  parameter {
    name         = "require_secure_transport"
    value        = "ON"
    apply_method = "immediate"
  }
```
Setting `require_secure_transport` to `"ON"` instructs the MySQL database instance to reject any client connection that does not use TLS/SSL encryption in transit, satisfying CKV2_AWS_69.

### Verification
Run the test with `pytest test_db_encryption_in_transit.py`. The test will confirm that `require_secure_transport` is configured to `ON` (or `1`) within the associated parameter group.