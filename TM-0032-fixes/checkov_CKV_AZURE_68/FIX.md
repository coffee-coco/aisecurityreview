### Vulnerability Explanation
Checkov rule `CKV_AZURE_68` enforces that Azure PostgreSQL servers have public network access disabled. When `public_network_access_enabled` is omitted or set to `true` in an `azurerm_postgresql_server` resource, Azure defaults to allowing public internet connections to reach the PostgreSQL server endpoint. This expands the attack surface, allowing internet-routed brute force attacks, credential spraying, and exploitation of potential database vulnerabilities from untrusted networks.

### Remediation
In `terraform/azure/sql.tf`, `public_network_access_enabled = false` was added to `azurerm_postgresql_server.example`. This ensures that public access is blocked and connections must be established via private endpoints or within a Virtual Network.

### Verification
Run `pytest test_azure_postgresql_public_access.py` (or execute via `python3 -m unittest test_azure_postgresql_public_access.py`). The test parses the `azurerm_postgresql_server.example` resource block from `terraform/azure/sql.tf` and asserts that `public_network_access_enabled` is explicitly present and set to `false`.