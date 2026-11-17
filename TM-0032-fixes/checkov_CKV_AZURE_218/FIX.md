### Vulnerability
Azure Application Gateway instances without an explicit `ssl_policy` configuration default to allowing deprecated TLS protocol versions (such as TLS 1.0 and TLS 1.1). Deprecated TLS versions have known cryptographic vulnerabilities (e.g., POODLE, BEAST) and do not meet modern security compliance standards (NIST SC-8, SC-8(1), SC-13).

### Evidence
In `terraform/azure/application_gateway.tf` at line 1, resource `azurerm_application_gateway.network` was declared without an `ssl_policy` block. As a result, Checkov rule `CKV_AZURE_218` ("Ensure Application Gateway defines secure protocols for in transit communication") failed.

### Fix
An `ssl_policy` block has been added to `azurerm_application_gateway.network` specifying `min_protocol_version = "TLSv1_2"`. This enforces TLS 1.2 as the minimum protocol version for transit communication.

### Verification
The attached unit test (`test_application_gateway_ssl_policy.py`) inspects `terraform/azure/application_gateway.tf` to confirm that `azurerm_application_gateway.network` contains an `ssl_policy` block with `min_protocol_version` set to either `TLSv1_2` or `TLSv1_3`. It fails against the original configuration and passes with the fix applied.