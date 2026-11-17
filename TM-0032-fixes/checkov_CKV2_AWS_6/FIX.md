### Vulnerability Explanation
Checkov rule `CKV2_AWS_6` checks that each AWS S3 bucket is configured with an S3 Public Access Block (`aws_s3_bucket_public_access_block`). 

Without an explicit Public Access Block attached to each bucket, objects and bucket policies are vulnerable to inadvertent exposure to the public Internet via accidental Access Control List (ACL) changes, policy misconfigurations, or identity delegation.

### Evidence Analysis
In the codebase, 6 S3 bucket resources lacked an `aws_s3_bucket_public_access_block`:
1. `terraform/aws/ec2.tf`: `aws_s3_bucket.flowbucket`
2. `terraform/aws/s3.tf`: `aws_s3_bucket.data`
3. `terraform/aws/s3.tf`: `aws_s3_bucket.financials`
4. `terraform/aws/s3.tf`: `aws_s3_bucket.operations`
5. `terraform/aws/s3.tf`: `aws_s3_bucket.data_science`
6. `terraform/aws/s3.tf`: `aws_s3_bucket.logs`

None of these resources had an associated `aws_s3_bucket_public_access_block` resource defined.

### Remediation
In `terraform/aws/ec2.tf` and `terraform/aws/s3.tf`, an `aws_s3_bucket_public_access_block` resource was added for each corresponding S3 bucket with all four protection flags enabled:
- `block_public_acls = true`
- `block_public_policy = true`
- `ignore_public_acls = true`
- `restrict_public_buckets = true`

### Verification
The attached unit test (`test_s3_public_access_block.py`) verifies that each identified S3 bucket in `ec2.tf` and `s3.tf` is associated with an `aws_s3_bucket_public_access_block` having all four public access prevention settings enabled. Running `pytest test_s3_public_access_block.py` fails on the unpatched codebase and passes once the fix is applied.