### Vulnerability Explanation
Checkov check `CKV_AZURE_53` flags Azure Database for MySQL instances that allow public network access. When `public_network_access_enabled` is set to `true`, the MySQL server is accessible over the public internet, relying solely on firewall rules and authentication credentials. This increases the exposure of the database to internet-based brute force attacks, credential spraying, and potential exploitation of MySQL vulnerabilities.

### Fix
In `terraform/azure/sql.tf`, line 59 was modified from:
```hcl
public_network_access_enabled     = true
```
to:
```hcl
public_network_access_enabled     = false
```
Disabling public network access ensures the database server can only be accessed through private endpoints (Private Link) within a virtual network, remediating `CKV_AZURE_53`.

### Verification
Run `pytest test_ckv_azure_53.py` or execute `checkov -f terraform/azure/sql.tf --check CKV_AZURE_53` to verify that `CKV_AZURE_53` passes.