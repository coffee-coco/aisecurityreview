### Vulnerability Description
In Azure, SQL servers created via Azure Resource Manager allow public network access by default if not explicitly disabled. Having public network access enabled exposes the database server endpoint directly to the public internet, increasing the attack surface to brute-force attacks, port scanning, and potential exploitation of database services.

### Why It Was Exploitable Here
In `terraform/azure/mssql.tf`, seven `azurerm_mssql_server` resources (`mssql1` through `mssql7`) omitted the `public_network_access_enabled` attribute. Because AzureRM defaults to enabling public network access when this attribute is not specified, all seven database servers would be provisioned reachable via public IP addresses.

### Fix Details
Set `public_network_access_enabled = false` in each `azurerm_mssql_server` resource (`mssql1` through `mssql7`) in `terraform/azure/mssql.tf`. This instructs Azure to block traffic originating from public internet IP addresses, requiring clients to connect via private endpoints or virtual network integrations.

### Verification
The attached unit test scans `terraform/azure/mssql.tf` and ensures every `azurerm_mssql_server` resource explicitly configures `public_network_access_enabled = false`, passing only when all server blocks have public access disabled.