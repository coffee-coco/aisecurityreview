### Vulnerability Details
Checkov rule `CKV_AZURE_52` flags `azurerm_mssql_server` resources that do not configure `minimum_tls_version` to `1.2`. Without an explicit minimum TLS version enforcement, Azure SQL Server allows connections negotiated with legacy TLS versions (e.g., TLS 1.0 or TLS 1.1), which suffer from known cryptographic vulnerabilities (such as POODLE and BEAST) and fail compliance standards (such as PCI DSS 3.1+).

### Evidence
In `terraform/azure/mssql.tf`, resources `mssql1` through `mssql7` (lines 20-151) defined `version`, `administrator_login`, and `administrator_login_password`, but omitted `minimum_tls_version`.

### Remediation
Added `minimum_tls_version = "1.2"` to all `azurerm_mssql_server` resources (`mssql1` through `mssql7`) in `terraform/azure/mssql.tf`. This forces all client connections to use TLS 1.2 or higher.

### Verification
The unit test in `test_mssql_tls.py` inspects each `azurerm_mssql_server` block in `terraform/azure/mssql.tf` and verifies that `minimum_tls_version` is present and set to `"1.2"`. It fails on the original codebase and passes once the fix is applied.