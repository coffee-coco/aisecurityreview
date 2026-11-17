### Vulnerability Explanation
Checkov rule `CKV_AWS_145` ensures that AWS S3 buckets are configured with default server-side encryption using AWS Key Management Service (KMS) (`sse_algorithm = "aws:kms"`). In the original configuration, five buckets lacked default encryption:
- `aws_s3_bucket.flowbucket` in `terraform/aws/ec2.tf` (lines 271-288)
- `aws_s3_bucket.data` in `terraform/aws/s3.tf` (lines 1-21)
- `aws_s3_bucket.financials` in `terraform/aws/s3.tf` (lines 42-63)
- `aws_s3_bucket.operations` in `terraform/aws/s3.tf` (lines 65-87)
- `aws_s3_bucket.data_science` in `terraform/aws/s3.tf` (lines 89-111)

Without explicit server-side encryption with KMS, objects uploaded to these buckets without explicit client-side or per-object encryption parameters are either unencrypted or default to standard S3-managed keys (SSE-S3), which does not provide KMS access policy governance, rotation controls, or audit logging via AWS CloudTrail.

### Fix Details
For each vulnerable `aws_s3_bucket` resource across `terraform/aws/ec2.tf` and `terraform/aws/s3.tf`, a `server_side_encryption_configuration` block was added matching the existing convention used in `aws_s3_bucket.logs`:
```hcl
server_side_encryption_configuration {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "${aws_kms_key.logs_key.arn}"
    }
  }
}
```
This configures default SSE-KMS encryption using the KMS key (`aws_kms_key.logs_key.arn`) defined within the Terraform project, remediating `CKV_AWS_145`.

### Verification
Run the test with:
```bash
pytest test_s3_kms_encryption.py
```
or:
```bash
python -m unittest test_s3_kms_encryption.py
```
The test asserts that each `aws_s3_bucket` block in `terraform/aws/ec2.tf` and `terraform/aws/s3.tf` contains a `server_side_encryption_configuration` with `sse_algorithm = "aws:kms"`.