### Vulnerability Description
Checkov check `CKV_AWS_382` (NIST SP 800-53 SC-7 Boundary Protection) flags security groups and security group rules that permit unrestricted outbound traffic to the entire public Internet (`0.0.0.0/0`) across all ports and protocols (`protocol = "-1"`, representing port -1 / all traffic). Unrestricted egress allows compromised instances to establish command-and-control (C2) channels, exfiltrate data, or participate in distributed attacks across arbitrary outbound ports.

### Exploitable Locations
1. `terraform/aws/db-app.tf` (`aws_security_group_rule.egress`, line 145):
   ```hcl
   resource "aws_security_group_rule" "egress" {
     type              = "egress"
     from_port         = 0
     to_port           = 0
     protocol          = "-1"
     cidr_blocks       = ["0.0.0.0/0"]
     security_group_id = "${aws_security_group.default.id}"
   }
   ```
   The RDS MySQL database security group was granted unrestricted outbound access to `0.0.0.0/0` across all protocols/ports. An RDS database instance has no legitimate operational need to initiate unrestricted outbound network connections to the public Internet.

2. `terraform/aws/ec2.tf` (`aws_security_group.web-node`, line 77, egress at line 97):
   ```hcl
   egress {
     from_port = 0
     to_port   = 0
     protocol  = "-1"
     cidr_blocks = [
     "0.0.0.0/0"]
   }
   ```
   The `web-node` security group applied to the web servers allowed unrestricted egress to `0.0.0.0/0` on all ports and protocols.

### Remediation
- In `terraform/aws/db-app.tf`, updated `aws_security_group_rule.egress` to scope outbound traffic strictly to the VPC CIDR block (`["${aws_vpc.web_vpc.cidr_block}"]`) instead of `0.0.0.0/0`.
- In `terraform/aws/ec2.tf`, updated the `egress` block in `aws_security_group.web-node` to restrict outbound traffic to the VPC CIDR block (`[aws_vpc.web_vpc.cidr_block]`), maintaining local VPC communication between the web nodes and the RDS instance without permitting unrestricted outbound internet egress on port -1.

### Verification
Run `pytest test_security_group_egress.py` or `python -m unittest test_security_group_egress.py` from the root of the repository. The test verifies that neither `aws_security_group_rule.egress` in `db-app.tf` nor `aws_security_group.web-node` in `ec2.tf` allows all-port/all-protocol egress to `0.0.0.0/0`.