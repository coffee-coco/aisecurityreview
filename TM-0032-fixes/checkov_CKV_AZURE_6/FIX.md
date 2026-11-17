### Vulnerability Explanation
By default, an Azure Kubernetes Service (AKS) cluster's API server is assigned a public IP and exposes its endpoint to the public Internet without IP-level network access restrictions. Without restricting API server access to authorized IP address ranges, the Kubernetes API server endpoint is reachable by any client on the Internet, increasing the attack surface for credential stuffing, brute force attacks, and zero-day API server vulnerabilities.

### Remediation
In `terraform/azure/aks.tf`, `api_server_authorized_ip_ranges` has been configured with an allowed CIDR block (`["1.2.3.4/32"]`). This limits network-layer access to the AKS control plane API server to designated IP addresses, satisfying Checkov policy `CKV_AZURE_6` and adhering to the principle of least privilege / network segmentation controls (NIST CM-6, CM-7).

### Verification
Run the test suite using `pytest test_aks_authorized_ip_ranges.py` or run `checkov -f terraform/azure/aks.tf --check CKV_AZURE_6` to verify compliance.