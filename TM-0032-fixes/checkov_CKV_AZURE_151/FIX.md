### Vulnerability Details
Checkov policy `CKV_AZURE_151` ensures that Azure Windows Virtual Machines have host-level disk encryption enabled (`encryption_at_host_enabled`). In `terraform/azure/instance.tf`, `azurerm_windows_virtual_machine.windows_machine` omitted this property, leaving it with the default value of `false`. Without Encryption at Host enabled, temporary caches, ephemeral disks, and data in transit between the host and Azure Storage may not be encrypted at the host VM compute level, violating NIST guidelines (SC-13, SC-28, SC-28(1)).

### Fix Details
In `terraform/azure/instance.tf`, `encryption_at_host_enabled = true` was added to `resource azurerm_windows_virtual_machine "windows_machine"`. This ensures that all OS, data, and temporary disks associated with this VM are encrypted end-to-end at the VM host.

### Verification
Run the test using `pytest test_windows_vm_encryption.py` (or `python3 -m unittest test_windows_vm_encryption.py`). You can also run `checkov -f terraform/azure/instance.tf --check CKV_AZURE_151` to verify policy compliance.