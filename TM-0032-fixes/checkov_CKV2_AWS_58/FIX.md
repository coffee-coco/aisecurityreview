### Vulnerability Details
Checkov rule `CKV2_AWS_58` requires deletion protection to be enabled on AWS Neptune clusters. By default, AWS Neptune cluster deletion protection is disabled (`deletion_protection = false`). Without deletion protection, a Neptune cluster can be deleted accidentally or maliciously via the AWS console, CLI, API, or an automated Terraform destroy/apply run, resulting in catastrophic and irreversible data loss.

### Fix
In `terraform/aws/neptune.tf`, `deletion_protection = true` was added to the `aws_neptune_cluster.default` resource block. This prevents any request to delete the Neptune cluster unless deletion protection is explicitly disabled first.

### Verification
The unit test in `test_neptune_deletion_protection.py` reads `terraform/aws/neptune.tf` and verifies that the `aws_neptune_cluster.default` resource defines `deletion_protection = true`. It fails on the original file and passes with this fix applied.