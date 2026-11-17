### Vulnerability Details
Checkov rule CKV_AZURE_29 flags PostgreSQL database servers that do not enforce SSL/TLS encrypted connections. In `terraform/azure/sql.tf`, the resource `azurerm_postgresql_server.example` explicitly configured `ssl_enforcement_enabled = false` at line 85. When SSL enforcement is disabled, network traffic between database clients and the database server can transmit credentials and queries in cleartext, exposing the data to eavesdropping and man-in-the-middle (MitM) attacks.

### Remediation
Updated line 85 of `terraform/azure/sql.tf` from `ssl_enforcement_enabled = false` to `ssl_enforcement_enabled = true` on `azurerm_postgresql_server.example`. This ensures Azure PostgreSQL requires all client connections to use encrypted SSL/TLS channels.

### Verification
Run the included test `test_ckv_azure_29.py` via `pytest test_ckv_azure_29.py` or run `checkov -f terraform/azure/sql.tf --check CKV_AZURE_29` to confirm that the CKV_AZURE_29 check passes.