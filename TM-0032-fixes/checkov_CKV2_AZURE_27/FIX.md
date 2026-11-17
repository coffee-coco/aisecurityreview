### Vulnerability Details
Azure SQL (MSSQL) database servers configured without an Azure Active Directory (Azure AD) administrator rely only on native SQL authentication (local user credentials). This violates security best practices and compliance standards (NIST IA-2, IA-8, CM-6; Checkov check `CKV2_AZURE_27`). Azure AD authentication centralizes identity lifecycle management, enables multi-factor authentication (MFA), role-based access control, and eliminates long-lived, static SQL passwords.

### Exploitation / Root Cause
In `terraform/azure/mssql.tf`, resources `azurerm_mssql_server.mssql1` through `mssql7` (lines 20-151) were declared with only local administrator credentials (`administrator_login` and `administrator_login_password`) and lacked any `azuread_administrator` configuration.

### Remediation
For each `azurerm_mssql_server` resource (`mssql1` through `mssql7`), an `azuread_administrator` configuration block was added with `login_username` and `object_id`. This enables Azure AD authentication on all SQL server instances.

### Verification
Run the test with `pytest test_mssql_azuread_auth.py` or `python3 -m unittest test_mssql_azuread_auth.py`. It confirms each `azurerm_mssql_server` resource block in `terraform/azure/mssql.tf` contains an `azuread_administrator` configuration block.