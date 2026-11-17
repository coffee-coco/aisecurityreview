### Vulnerability Details
Checkov policy `CKV_AWS_24` flags security groups that allow ingress traffic from the public internet (`0.0.0.0/0`) on port 22 (SSH). Opening port 22 to the public internet leaves instances exposed to automated brute-force attacks, port scanning, and potential remote compromise if authentication keys or credentials are weak or leaked.

### Evidence
In `terraform/aws/ec2.tf`, lines 90-96:
```terraform
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
    "0.0.0.0/0"]
  }
```
The `aws_security_group.web-node` explicitly allows unrestricted inbound SSH traffic from `0.0.0.0/0`.

### Remediation
The ingress rule for port 22 in `aws_security_group.web-node` was modified to restrict incoming traffic to the internal VPC CIDR range (`172.16.0.0/16`) instead of `0.0.0.0/0`. This ensures SSH access is only permissible from within the local network while maintaining expected web traffic (port 80) for the public internet.

### Verification
The unit test in `test_ssh_ingress.py` parses `terraform/aws/ec2.tf`, extracts ingress rules from `aws_security_group.web-node`, and asserts that no rule covering port 22 includes `0.0.0.0/0` in `cidr_blocks`.