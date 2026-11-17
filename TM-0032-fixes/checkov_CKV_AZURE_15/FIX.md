### Vulnerability
The Azure App Service resource `azurerm_app_service.app-service1` configured its minimum TLS version to TLS 1.1 (`min_tls_version = "1.1"`). TLS 1.0 and 1.1 are deprecated protocols susceptible to known cryptographic attacks (such as BEAST, POODLE, and downgrade attacks) and fail modern security compliance standards (such as PCI DSS and NIST recommendations).

### Remediation
In `terraform/azure/app_service.tf`, inside the `site_config` block for `azurerm_app_service.app-service1`, `min_tls_version` was updated from `"1.1"` to `"1.2"`. This ensures that inbound connections to the web app enforce TLS 1.2 or higher, remediating Checkov rule CKV_AZURE_15.

### Verification
Run the test with `pytest test_tls_version.py` or execute `checkov -f terraform/azure/app_service.tf -c CKV_AZURE_15` to verify compliance.