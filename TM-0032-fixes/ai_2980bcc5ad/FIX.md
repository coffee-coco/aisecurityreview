### Vulnerability Description
A single pseudorandom string (`random_string.password.result`) was shared across heterogeneous Azure resources: the Linux virtual machine (`azurerm_linux_virtual_machine.linux_machine`), the Windows virtual machine (`azurerm_windows_virtual_machine.windows_machine`), the MySQL database server (`azurerm_mysql_server.example`), and an Azure Key Vault secret (`azurerm_key_vault_secret.secret`). In addition to cross-service credential reuse, `random_string` produces non-sensitive outputs in Terraform state and logs compared to `random_password`.

This cross-boundary credential sharing creates severe lateral movement risk: compromising a lower-privilege database instance (e.g. via SQL injection or leaked database connection strings) immediately yields root administrator passwords to all VMs and Key Vault secrets.

### Remediation
1. Replaced the single shared `random_string.password` in `terraform/azure/instance.tf` with distinct `random_password` resources: `random_password.linux_password` for the Linux VM and `random_password.windows_password` for the Windows VM.
2. Introduced a dedicated `random_password.mysql_password` resource in `terraform/azure/sql.tf` for the MySQL server instance.
3. Introduced a dedicated `random_password.key_vault_secret` resource in `terraform/azure/key_vault.tf` for the Key Vault secret.
4. Using `random_password` ensures that passwords are independently generated per service boundary and are treated as sensitive attributes by Terraform.

### Verification
Run `pytest test_cross_service_shared_credentials.py` from the repository root to verify that distinct password references are configured for all four resources and that no cross-service credential sharing exists.