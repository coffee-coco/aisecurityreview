### Vulnerability Details
Checkov rule `CKV_AWS_189` requires that EBS volumes are encrypted using AWS KMS Customer Managed Keys (CMKs). Leaving EBS volumes unencrypted or encrypted with default AWS-managed keys lacks granular access control, audit logging, and custom key rotation policies. If storage volumes are compromised or accessed without encryption, sensitive data at rest can be exposed in violation of NIST SC-12, SC-13, and SC-28 controls.

### Exploitable Evidence
In `terraform/aws/ec2.tf` lines 34-51, resource `aws_ebs_volume.web_host_storage` had no active encryption configuration (the `encrypted` attribute was commented out and `kms_key_id` was absent):
```hcl
resource "aws_ebs_volume" "web_host_storage" {
  # unencrypted volume
  availability_zone = "${var.region}a"
  #encrypted         = false  # Setting this causes the volume to be recreated on apply 
  size = 1
...
}
```

### Fix Details
1. Added resource `aws_kms_key.web_host_storage_key` to `terraform/aws/ec2.tf` with key rotation enabled (`enable_key_rotation = true`).
2. Updated `aws_ebs_volume.web_host_storage` to configure `encrypted = true` and `kms_key_id = aws_kms_key.web_host_storage_key.arn`.

### Verification
- Run the unit test: `pytest test_ebs_volume_cmk_encryption.py` (fails against unencrypted volume and passes after applying the patch).
- Run Checkov against the Terraform directory: `checkov -f terraform/aws/ec2.tf --check CKV_AWS_189`.