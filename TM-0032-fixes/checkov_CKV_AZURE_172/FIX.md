### Vulnerability Explanation
Checkov rule `CKV_AZURE_172` checks that Azure Kubernetes Service (AKS) clusters enable secret rotation for the Secrets Store CSI Driver (`key_vault_secrets_provider`). Without automatic secret rotation enabled, secrets retrieved from Azure Key Vault and mounted into pods become stale when rotated in Key Vault. Stale secrets can cause operational outages or encourage anti-patterns such as long-lived, unrotated credentials and tokens, increasing the window of exposure in the event of credential compromise.

### Remediation
In `terraform/azure/aks.tf`, the `azurerm_kubernetes_cluster.k8s_cluster` resource was updated to include the `key_vault_secrets_provider` block with `secret_rotation_enabled = true`. This enables the Key Vault Secrets Provider add-on and configures periodic polling to automatically update mounted secrets and Kubernetes secret objects when secrets in Azure Key Vault are rotated.

### Verification
Run the test with `pytest test_aks_secrets_rotation.py` (or `python -m unittest test_aks_secrets_rotation.py`). It validates that `azurerm_kubernetes_cluster.k8s_cluster` contains the `key_vault_secrets_provider` block with `secret_rotation_enabled = true`.