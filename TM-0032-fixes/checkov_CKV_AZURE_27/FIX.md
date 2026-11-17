### Vulnerability Explanation
Checkov rule `CKV_AZURE_27` checks that 'Email service and co-administrators' is enabled on Azure SQL/MSSQL server security alert policies (`azurerm_mssql_server_security_alert_policy`).

In the Terraform Azure provider, the attribute `email_account_admins` controls whether security alert notifications are automatically sent to subscription co-administrators and service administrators. By default, `email_account_admins` is `false`. When omitted, security administrators may not receive immediate notifications about detected security incidents, anomalous database access attempts, or threat detections on the MSSQL servers.

### Remediation
In both `terraform/azure/mssql.tf` and `terraform/azure/sql.tf`, each of the 8 `azurerm_mssql_server_security_alert_policy` resources (`alertpolicy1` through `alertpolicy7` in `mssql.tf`, and `example` in `sql.tf`) was updated to include:
```terraform
  email_account_admins = true
```
This enables email alerting to subscription administrators, satisfying Checkov policy `CKV_AZURE_27`.

### Verification
Run the test via `pytest test_mssql_alert_policy_email_admins.py` or run `checkov -f terraform/azure/mssql.tf -f terraform/azure/sql.tf --check CKV_AZURE_27` to verify compliance.