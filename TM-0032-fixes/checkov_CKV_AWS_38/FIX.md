### Vulnerability Explanation
In AWS EKS, the Kubernetes API server endpoint can be accessed via private subnets, a public IP endpoint, or both. By default in Terraform's `aws_eks_cluster` resource, `endpoint_public_access` is `true` and `public_access_cidrs` defaults to `["0.0.0.0/0"]`. 

In `terraform/aws/eks.tf`, `aws_eks_cluster.eks_cluster` enables private access (`endpoint_private_access = true`), but leaves `endpoint_public_access` unspecified. As a result, the Kubernetes API server remains publicly accessible from the entire internet (`0.0.0.0/0`), failing Checkov policy `CKV_AWS_38` and exposing the cluster control plane to internet-based discovery and potential brute-force or exploitation attempts.

### Remediation
In `terraform/aws/eks.tf`, `endpoint_public_access = false` was added to the `vpc_config` block inside `aws_eks_cluster.eks_cluster`. With `endpoint_private_access = true` already set, communication with the cluster API endpoint is confined to the VPC and private subnets, eliminating unrestricted public access from `0.0.0.0/0`.

### Verification
Run the test using `pytest test_eks_public_access.py` (or `python3 -m unittest test_eks_public_access.py`). It parses `terraform/aws/eks.tf` and checks that the EKS cluster either explicitly sets `endpoint_public_access = false` or restricts `public_access_cidrs` away from `0.0.0.0/0`. The test fails on the unpatched file and passes with this fix.