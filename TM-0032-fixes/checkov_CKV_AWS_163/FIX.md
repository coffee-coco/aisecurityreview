### Vulnerability Description
AWS Elastic Container Registry (ECR) repositories can automatically scan container images for known vulnerabilities (Common Vulnerabilities and Exposures, CVEs) whenever an image is pushed. If `scan_on_push` is omitted or disabled, vulnerable container images can be pushed into the repository and deployed into production without early detection, violating security controls CM-6 and RA-5.

### Root Cause in Code
In `terraform/aws/ecr.tf`, the resource `aws_ecr_repository.repository` omitted the `image_scanning_configuration` block. By default, ECR repositories do not enable automated scanning on push unless explicitly declared.

### Remediation
Added the `image_scanning_configuration` block with `scan_on_push = true` to `aws_ecr_repository.repository`. This satisfies Checkov rule `CKV_AWS_163`.

### Verification
Run `pytest test_ecr_scan_on_push.py` from the root of the repository or run Checkov (`checkov -f terraform/aws/ecr.tf -c CKV_AWS_163`).