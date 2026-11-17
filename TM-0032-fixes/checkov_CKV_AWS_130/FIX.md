### Vulnerability Explanation
Checkov rule `CKV_AWS_130` requires that AWS VPC subnets do not automatically assign public IP addresses to instances launched into them (`map_public_ip_on_launch = false`).

In both `terraform/aws/ec2.tf` and `terraform/aws/eks.tf`, all four subnets (`web_subnet`, `web_subnet2`, `eks_subnet1`, `eks_subnet2`) had `map_public_ip_on_launch = true`. Enabling automatic public IP assignment causes instances and worker nodes placed in these subnets to receive publicly routable IP addresses by default, increasing attack surface and exposing internal services to unsolicited inbound traffic directly from the internet.

### Fix
Updated `map_public_ip_on_launch = false` for:
1. `aws_subnet.web_subnet` in `terraform/aws/ec2.tf`
2. `aws_subnet.web_subnet2` in `terraform/aws/ec2.tf`
3. `aws_subnet.eks_subnet1` in `terraform/aws/eks.tf`
4. `aws_subnet.eks_subnet2` in `terraform/aws/eks.tf`

### Verification
Run the test via `pytest test_subnet_public_ip.py` (or `python3 -m unittest test_subnet_public_ip.py`), or run Checkov (`checkov -f terraform/aws/ec2.tf -f terraform/aws/eks.tf -c CKV_AWS_130`), and verify that CKV_AWS_130 passes.