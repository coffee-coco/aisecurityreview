### Vulnerability
Checkov rule `CKV_AWS_8` enforces encryption at rest for Elastic Block Store (EBS) volumes attached to EC2 instances (`aws_instance`, `aws_launch_configuration`, and `aws_launch_template`).

In both `terraform/aws/db-app.tf` (line 243 for `aws_instance.db_app`) and `terraform/aws/ec2.tf` (line 1 for `aws_instance.web_host`), EC2 instance resources were defined without an explicit `root_block_device` configuration block specifying `encrypted = true`. Without this, default instance launches in AWS may provision unencrypted root EBS volumes, leaving data at rest unprotected against unauthorized physical access, media theft, or regulatory compliance violations (NIST SC-13, SC-28).

### Fix
Configured a `root_block_device` block with `encrypted = true` on both affected `aws_instance` resources:
1. `terraform/aws/db-app.tf` on `aws_instance.db_app`
2. `terraform/aws/ec2.tf` on `aws_instance.web_host`

### Verification
Run the test using `pytest test_ec2_root_volume_encryption.py` (or `python -m unittest test_ec2_root_volume_encryption.py`). You can also run Checkov directly with `checkov -c CKV_AWS_8 -d terraform/aws/` to verify that both resources now pass the check.