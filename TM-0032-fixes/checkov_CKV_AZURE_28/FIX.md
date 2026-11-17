### Vulnerability Analysis
Checkov rule `CKV_AZURE_28` ensures that SSL connection enforcement is enabled on Azure Database for MySQL servers. In `terraform/azure/sql.tf`, line 60 explicitly set `ssl_enforcement_enabled = false` for `azurerm_mysql_server.example`. Disabling SSL enforcement allows unencrypted client-server communication, exposing sensitive data, queries, and credentials in transit to eavesdropping and man-in-the-middle (MitM) attacks (violating NIST SC-8 / SC-13 controls).

### Remediation
In `terraform/azure/sql.tf`, `ssl_enforcement_enabled` was updated from `false` to `true` on the `azurerm_mysql_server.example` resource block. This forces all client connections to the MySQL database server to be encrypted via SSL/TLS.

### Verification
Run `pytest test_mysql_ssl_enforcement.py` or run `checkov -f terraform/azure/sql.tf --check CKV_AZURE_28` to confirm the check passes.