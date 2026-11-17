### Vulnerability Details
By default, Azure Key Vault allows public network traffic over the Internet if not explicitly restricted (`public_network_access_enabled = true` by default in Azure and the `azurerm` Terraform provider). Leaving public network access enabled exposes the Key Vault endpoint to public internet routing, increasing the attack surface for unauthorized reconnaissance and access attempts.

### Remediation
In `terraform/azure/key_vault.tf`, `public_network_access_enabled = false` was added to `azurerm_key_vault.example`. This ensures that public network access is disabled at the vault level, satisfying policy `CKV_AZURE_189` and enforcing that connectivity must be routed through private endpoints or authorized private network configurations.

### Verification
Run `pytest test_key_vault_public_access.py` to confirm that `azurerm_key_vault.example` explicitly specifies `public_network_access_enabled = false`. Running Checkov against the Terraform directory (`checkov -f terraform/azure/key_vault.tf --check CKV_AZURE_189`) will also confirm the rule passes.