### Vulnerability
Checkov rule `CKV2_AZURE_42` verifies that Azure PostgreSQL servers are configured with an Azure Private Endpoint (`azurerm_private_endpoint`). Without a private endpoint, database traffic may be exposed to the public internet, increasing the attack surface for unauthorized network access, data interception, and brute-force authentication attacks.

### Exploitation & Evidence
In `terraform/azure/sql.tf`, line 73 defines `azurerm_postgresql_server.example` without configuring an associated `azurerm_private_endpoint` resource connected to it via a `private_service_connection`. As a result, the PostgreSQL server is not integrated into a private virtual network subnet via Private Link.

### Fix
An `azurerm_private_endpoint` resource (`azurerm_private_endpoint.postgresql`) was added to `terraform/azure/sql.tf`. It establishes a `private_service_connection` targeting `azurerm_postgresql_server.example.id` with `subresource_names = ["postgresqlServer"]`, fulfilling the requirement of `CKV2_AZURE_42` by ensuring the PostgreSQL server is reachable privately via Azure Private Link.

### Verification
Run `pytest test_azure_postgresql_private_endpoint.py` from the repository root (or run `checkov -f terraform/azure/sql.tf -c CKV2_AZURE_42`).