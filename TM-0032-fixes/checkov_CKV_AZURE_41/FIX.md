### Vulnerability Explanation
Checkov rule `CKV_AZURE_41` requires that Key Vault secrets have an expiration date set. Secrets without an expiration date remain active indefinitely unless manually rotated or deleted. If a secret is compromised or left unmanaged, the lack of an expiration policy increases the attack surface and window of opportunity for attackers to utilize the credentials, conflicting with security standards such as NIST CM-6 and IA-5.

### Fix Explanation
In `terraform/azure/key_vault.tf`, the resource `azurerm_key_vault_secret.secret` was defined without the `expiration_date` property. Adding `expiration_date = "2025-12-31T23:59:59Z"` ensures an explicit expiration timestamp is assigned to the secret, satisfying Checkov policy `CKV_AZURE_41`.

### Verification
- Run the provided unit test: `pytest test_key_vault_secret_expiration.py`. It inspects the `azurerm_key_vault_secret.secret` block in `terraform/azure/key_vault.tf` to confirm that `expiration_date` is defined.
- Run Checkov against the Azure Terraform directory (`checkov -d terraform/azure -c CKV_AZURE_41`) to verify the check passes.