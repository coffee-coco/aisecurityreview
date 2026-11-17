### Vulnerability Analysis
Checkov rule `CKV_AZURE_217` requires that Azure Application Gateway listeners do not allow unencrypted HTTP traffic. In `terraform/azure/application_gateway.tf`, the `azurerm_application_gateway.network` resource defined an `http_listener` with `protocol = "Http"` (lines 42–47). Serving connections over plaintext HTTP exposes web traffic to eavesdropping, interception, and man-in-the-middle (MitM) attacks.

### Remediation
In `terraform/azure/application_gateway.tf`, the listener's `protocol` property within the `http_listener` block was updated from `"Http"` to `"Https"`. This ensures all incoming listener requests are encrypted in transit via TLS/HTTPS.

### Verification
- Run `pytest test_application_gateway_http_listener.py` (or `python3 -m unittest test_application_gateway_http_listener.py`). It parses `terraform/azure/application_gateway.tf` and asserts that the listener protocol is configured to HTTPS instead of HTTP.
- Run Checkov against the Terraform directory (`checkov -f terraform/azure/application_gateway.tf --check CKV_AZURE_217`) to verify the check passes.