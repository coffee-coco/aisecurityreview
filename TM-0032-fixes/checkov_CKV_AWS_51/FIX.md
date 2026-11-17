### Vulnerability Details
Checkov rule `CKV_AWS_51` verifies that AWS ECR repositories are configured with image tag immutability enabled. In `terraform/aws/ecr.tf`, line 3 explicitly sets `image_tag_mutability = "MUTABLE"`.

### Impact
When mutable image tags are allowed, an attacker or compromised CI/CD pipeline can push a modified or malicious container image over an existing tag (such as `latest` or release version tags like `v1.0.0`). Downstream workloads pulling those tags will inadvertently run the altered image, leading to supply-chain attacks, software integrity violations, and deployment inconsistencies.

### Remediation
Changed `image_tag_mutability = "MUTABLE"` to `image_tag_mutability = "IMMUTABLE"` in `terraform/aws/ecr.tf`. This prevents overwriting existing image tags and ensures each image tag uniquely and permanently references a specific container image manifest.

### Verification
Run the test `pytest test_ecr_immutability.py` or run Checkov (`checkov -f terraform/aws/ecr.tf -c CKV_AWS_51`), both of which verify that `image_tag_mutability` is set to `"IMMUTABLE"`.