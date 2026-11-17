### Vulnerability Details
Checkov rule `CKV_AZURE_36` verifies that Azure Storage Account network rules allow access from Trusted Microsoft Services. In `terraform/azure/storage.tf`, the resource `azurerm_storage_account_network_rules.test` configures `default_action = "Deny"` and sets `bypass = ["Metrics"]`.

Because `AzureServices` is omitted from the `bypass` list, trusted first-party Azure services (such as Azure Backup, Azure Site Recovery, DevTest Labs, Event Grid, and Azure Monitor) that operate from outside the storage account's network boundary are blocked from accessing the storage account. This can break critical operational, monitoring, logging, and backup functionality.

### Remediation
In `terraform/azure/storage.tf`, `bypass` on `azurerm_storage_account_network_rules.test` was updated to include `"AzureServices"` (`bypass = ["Metrics", "AzureServices"]`). This enables trusted Microsoft platform services to bypass the storage firewall while preserving the denied default action and explicit IP restrictions for all other traffic.

### Verification
The unit test reads `terraform/azure/storage.tf` and parses the `azurerm_storage_account_network_rules.test` resource to verify that `"AzureServices"` is present in the `bypass` list. Running `pytest test_storage_network_rules.py` fails on the original code and passes with the fix applied.