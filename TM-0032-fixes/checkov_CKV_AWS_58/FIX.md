### Vulnerability Details
By default, Amazon EKS does not enable envelope encryption of Kubernetes secrets stored in `etcd`. Without envelope encryption, secrets stored in `etcd` are only protected by standard EBS volume encryption on AWS-managed control plane nodes, making secrets accessible in plaintext if access to the etcd key-value store or snapshots is obtained. Checkov rule `CKV_AWS_58` enforces that an `aws_eks_cluster` resource configures secrets envelope encryption using an AWS KMS Customer Master Key (CMK).

In `terraform/aws/eks.tf` (lines 118–141), `aws_eks_cluster.eks_cluster` was declared without an `encryption_config` block, leaving cluster secrets unencrypted at rest.

### Fix Details
1. Added an `aws_kms_key.eks_kms_key` resource with `enable_key_rotation = true` to provide a dedicated AWS KMS key for envelope encryption.
2. Added an `encryption_config` block inside `aws_eks_cluster.eks_cluster` pointing `provider.key_arn` to `aws_kms_key.eks_kms_key.arn` and setting `resources = ["secrets"]`.

### Verification
Run `pytest test_eks_secrets_encryption.py` or run `checkov -f terraform/aws/eks.tf --check CKV_AWS_58` to confirm the check passes.