### Vulnerability
By default, Amazon EKS does not export control plane logs to Amazon CloudWatch Logs. Without control plane logging enabled, critical security events (such as unauthorized API calls, authentication requests, audit trails, and cluster controller actions) are not recorded or monitored. This violates Checkov policy `CKV_AWS_37` and security control standards (e.g. NIST AU-2, AU-3, AU-12).

### Exploitation & Evidence
In `terraform/aws/eks.tf` (lines 118–141), the resource `aws_eks_cluster.eks_cluster` is defined without the `enabled_cluster_log_types` argument. As a result, the created EKS cluster runs without control plane logging enabled for any log stream.

### Remediation
Added `enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]` to the `aws_eks_cluster.eks_cluster` resource in `terraform/aws/eks.tf`. This ensures all five control plane log types (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`) are enabled and exported to CloudWatch Logs upon cluster deployment.

### Verification
Run `pytest test_eks_logging.py` (or execute the test with `python -m unittest test_eks_logging.py`). The test parses `aws_eks_cluster.eks_cluster` and confirms that all required log types are declared in `enabled_cluster_log_types`.