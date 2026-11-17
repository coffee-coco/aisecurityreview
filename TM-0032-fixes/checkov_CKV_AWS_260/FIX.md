### Vulnerability Details
Checkov rule `CKV_AWS_260` checks that no AWS Security Group allows unrestricted ingress access (`0.0.0.0/0` or `::/0`) to port 80 (HTTP). Allowing unrestricted ingress on port 80 exposes instances directly to the public internet using cleartext, unencrypted HTTP traffic, increasing attack surface for automated scans, eavesdropping, and man-in-the-middle attacks.

In `terraform/aws/ec2.tf` (lines 83–89), the `aws_security_group.web-node` resource defined an ingress rule allowing traffic to port 80 from CIDR block `"0.0.0.0/0"`.

### Remediation
The ingress rule for port 80 in `aws_security_group.web-node` was updated so that `cidr_blocks` is restricted to the VPC CIDR block `"172.16.0.0/16"` rather than `"0.0.0.0/0"`. This satisfies Checkov check `CKV_AWS_260` while allowing legitimate internal/VPC traffic to reach the web server.

### Verification
Run the test with:
```bash
pytest test_security_group_port_80.py
```
Or run Checkov on the Terraform file:
```bash
checkov -f terraform/aws/ec2.tf --check CKV_AWS_260
```