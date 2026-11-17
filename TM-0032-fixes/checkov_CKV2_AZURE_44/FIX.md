### Vulnerability Details
Checkov check `CKV2_AZURE_44` flags Azure MySQL servers that lack a private endpoint configuration. In `terraform/azure/sql.tf`, the resource `azurerm_mysql_server.example` was defined without an associated `azurerm_private_endpoint`. Without private endpoints, network communication to the MySQL server traverses the public internet or standard endpoints, increasing attack surface and exposure to external network threats.

### Fix Details
An `azurerm_private_endpoint` resource (`azurerm_private_endpoint.mysql`) has been added to `terraform/azure/sql.tf` connecting to `azurerm_mysql_server.example.id` with the `mysqlServer` subresource name. This enables private IP connectivity from the virtual network subnet to the database instance.

### Verification
Run `pytest test_mysql_private_endpoint.py` (or execute the test with `python -m unittest test_mysql_private_endpoint.py`). The test fails when run against the original code because no private endpoint is linked to `azurerm_mysql_server.example`, and passes once the endpoint configuration is in place.