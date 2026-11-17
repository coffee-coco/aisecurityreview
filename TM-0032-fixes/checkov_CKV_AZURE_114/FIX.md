### Vulnerability Description
Checkov rule `CKV_AZURE_114` checks that Azure Key Vault secrets define a `content_type` attribute. Without setting `content_type`, consumers and automated secret management tooling (such as rotation scripts or identity systems) cannot determine the format or intended handling of the secret (e.g., whether it is a password, connection string, PEM certificate, or plain text). Setting `content_type` aids in data classification, auditing, and secure programmatic processing.

### Fix Details
In `terraform/azure/key_vault.tf`, the resource `azurerm_key_vault_secret.secret` was missing the `content_type` attribute. Added `content_type = "text/plain"` to the resource block.

### Verification
Run `pytest test_key_vault_secret_content_type.py` (or execute `checkov -f terraform/azure/key_vault.tf --check CKV_AZURE_114`) to verify the secret resource now sets `content_type` and satisfies the check.