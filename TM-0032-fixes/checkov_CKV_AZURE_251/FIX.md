### Vulnerability Explanation
By default in Azure and the Terraform `azurerm` provider, `azurerm_managed_disk` resources have `public_network_access_enabled` set to `true`. When public network access is enabled, managed disks can be exported or imported directly over the public internet via Shared Access Signature (SAS) URIs, allowing potential exfiltration of virtual machine disk snapshots or unauthorized access.

Checkov rule `CKV_AZURE_251` checks that Azure Virtual Machine managed disks explicitly disable public network access.

### Remediation
In `terraform/azure/storage.tf`, `public_network_access_enabled = false` was added to `azurerm_managed_disk.example`. This ensures that data access is restricted to private endpoints within the virtual network and cannot be accessed over the public internet.

### Verification
The unit test reads `terraform/azure/storage.tf`, parses the `azurerm_managed_disk.example` block, and validates that `public_network_access_enabled` is explicitly configured to `false`. Running `pytest test_managed_disk_public_access.py` confirms that the vulnerability is remediated.