### Vulnerability Explanation
Checkov rule `CKV2_AWS_2` requires that EBS volumes attached to EC2 instances are encrypted at rest. In `terraform/aws/ec2.tf`, the `aws_ebs_volume.web_host_storage` resource had encryption omitted (and previously commented out as `#encrypted = false`), and it is attached to the `aws_instance.web_host` via `aws_volume_attachment.ebs_att`. Unencrypted EBS volumes leave stored data exposed if the underlying storage media is compromised or if snapshots are taken and inadvertently shared or improperly secured.

### Remediation
In `terraform/aws/ec2.tf` under `aws_ebs_volume.web_host_storage`:
- Added `encrypted = true` to enable AWS EBS encryption at rest.
- Removed the commented-out `encrypted = false` line and associated comment.

### Verification
The unit test in `test_ebs_volume_encryption.py` inspects `terraform/aws/ec2.tf` to verify that `aws_ebs_volume.web_host_storage` explicitly specifies `encrypted = true` as an active attribute. It fails against the unencrypted original configuration and passes once the fix is applied.