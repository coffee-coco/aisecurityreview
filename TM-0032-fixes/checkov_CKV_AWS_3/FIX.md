### Vulnerability
AWS EBS volumes without encryption store data at rest in plaintext. If an attacker gains unauthorized access to the underlying storage media, snapshots, or volume backups, unencrypted data can be exposed. Checkov policy CKV_AWS_3 requires all EBS volumes (`aws_ebs_volume`) to have data encryption enabled.

### Evidence
In `terraform/aws/ec2.tf` at line 34, the resource `aws_ebs_volume.web_host_storage` does not enable encryption; the `encrypted` attribute was commented out (`#encrypted = false`), leaving the volume unencrypted by default.

### Remediation
In `terraform/aws/ec2.tf`, set `encrypted = true` on the `aws_ebs_volume.web_host_storage` resource.

### Verification
Run `pytest test_ebs_encryption.py` (or `python3 -m unittest test_ebs_encryption.py`) or run Checkov (`checkov -f terraform/aws/ec2.tf --check CKV_AWS_3`) to confirm that CKV_AWS_3 passes.