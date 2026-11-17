### Vulnerability Explanation
Checkov rule `CKV_AWS_355` flags IAM policies that grant permissions on restrictable actions (actions that support resource-level permissions, such as `s3:*`, `ec2:*`, `rds:*`, `lambda:*`, and `cloudwatch:*`) while setting `Resource` to `"*"` (NIST SP 800-53 AC-3, AC-6).

In `terraform/aws/db-app.tf` (`aws_iam_role_policy.ec2policy`), actions `s3:*`, `ec2:*`, and `rds:*` were allowed across all resources (`"Resource": "*"`). Similarly, in `terraform/aws/iam.tf` (`aws_iam_user_policy.userpolicy`), actions `ec2:*`, `s3:*`, `lambda:*`, and `cloudwatch:*` were allowed across all resources (`"Resource": "*"`). If credentials associated with this EC2 instance profile or IAM user are compromised, an attacker would have unrestricted authority over all resources across the entire AWS account rather than being restricted to specific resources required for the workload.

### Remediation
1. In `terraform/aws/db-app.tf`, the wildcard `"Resource": "*"` on `aws_iam_role_policy.ec2policy` was scoped down to specific resource ARNs: the database instance ARN `${aws_db_instance.default.arn}`, scoped S3 bucket prefix ARN `arn:aws:s3:::${local.resource_prefix.value}-bucket/*`, and EC2 instance ARN pattern `arn:aws:ec2:*:*:instance/*`.
2. In `terraform/aws/iam.tf`, the wildcard `"Resource": "*"` on `aws_iam_user_policy.userpolicy` was scoped down to appropriate resource ARNs (`arn:aws:ec2:*:*:instance/*`, `arn:aws:s3:::${local.resource_prefix.value}-bucket/*`, `arn:aws:lambda:*:*:function:*`, and `arn:aws:cloudwatch:*:*:alarm:*`).

### Verification
Run `pytest test_iam_no_star_resource.py` or run `checkov -c CKV_AWS_355 -f terraform/aws/db-app.tf -f terraform/aws/iam.tf`. Both checks will pass.