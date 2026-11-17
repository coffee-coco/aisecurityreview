### Vulnerability Explanation
Checkov policy `CKV2_AZURE_7` requires that Azure SQL Server instances have Azure Active Directory (Azure AD) administrator configured. Configuring Azure AD authentication allows centralized identity and access management, enforces Multi-Factor Authentication (MFA), and eliminates reliance solely on SQL local username/password credentials which are vulnerable to brute-force attacks and credential leakage.

In `terraform/azure/sql.tf`, the resource `azurerm_sql_server.example` only configured local SQL authentication (`administrator_login` and `administrator_login_password`) without configuring an associated `azurerm_sql_active_directory_administrator` resource.

### Fix Details
An `azurerm_sql_active_directory_administrator` resource named `example` was added to `terraform/azure/sql.tf`. It references `azurerm_sql_server.example.name`, `azurerm_resource_group.example.name`, and the Azure AD tenant and principal object ID available from `data.azurerm_client_config.current`.

### Verification
Run the test using `pytest test_azure_sql_ad_admin.py` (or `python -m unittest test_azure_sql_ad_admin.py`) to verify that the `azurerm_sql_active_directory_administrator` resource is properly declared and linked to `azurerm_sql_server.example.name`. You can also run Checkov (`checkov -f terraform/azure/sql.tf -c CKV2_AZURE_7`) to confirm the check passes.