### Vulnerability Explanation
Checkov rule CKV_AZURE_130 verifies that Azure Database for PostgreSQL servers have infrastructure encryption enabled. Infrastructure encryption adds a second layer of encryption (using service-managed keys) at the hardware/storage layer beneath Azure's default storage service encryption. This provides double encryption at rest to satisfy NIST SC-13, SC-28, and SC-28(1) requirements.

In `terraform/azure/sql.tf`, the resource `azurerm_postgresql_server.example` omitted the `infrastructure_encryption_enabled` argument. In the `azurerm` Terraform provider, this defaults to `false` (disabled), leaving the PostgreSQL data without hardware-layer double encryption.

### Remediation
In `terraform/azure/sql.tf`, `infrastructure_encryption_enabled = true` was added to `azurerm_postgresql_server.example` (mirroring the configuration already present on `azurerm_mysql_server.example`).

### Verification
Run `pytest test_postgresql_infrastructure_encryption.py` or run `checkov -f terraform/azure/sql.tf -c CKV_AZURE_130` to confirm that the check passes.