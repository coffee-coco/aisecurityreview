### Vulnerability Explanation
Checkov rule `CKV_AZURE_54` checks that Azure MySQL servers enforce TLS version 1.2 (`ssl_minimal_tls_version_enforced = "TLS1_2"`). In `terraform/azure/sql.tf`, the resource `azurerm_mysql_server.example` does not configure the `ssl_minimal_tls_version_enforced` attribute. Older TLS versions (TLS 1.0 and TLS 1.1) suffer from known cryptographic vulnerabilities and weak cipher suites, making connections susceptible to eavesdropping and downgrade attacks.

### Fix
In `terraform/azure/sql.tf`, `ssl_minimal_tls_version_enforced = "TLS1_2"` was added to `azurerm_mysql_server.example`. This ensures that connections to the Azure MySQL instance must use TLS 1.2 or higher.

### Verification
Run the unit test `test_azure_mysql_tls.py` using `pytest test_azure_mysql_tls.py`. It inspects the `azurerm_mysql_server.example` definition in `terraform/azure/sql.tf` and asserts that `ssl_minimal_tls_version_enforced` is explicitly defined and set to `"TLS1_2"`. You can also verify by running Checkov: `checkov -f terraform/azure/sql.tf -c CKV_AZURE_54`.