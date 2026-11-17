### Vulnerability Details
Checkov rule `CKV_AWS_39` checks that Amazon EKS cluster API servers do not have public endpoints enabled. In AWS EKS and the Terraform AWS provider, the `endpoint_public_access` attribute inside `vpc_config` defaults to `true`. When enabled, the Kubernetes API server endpoint is reachable from the public Internet, unnecessarily exposing the control plane to scanning, brute-force attacks, and potential vulnerabilities in the Kubernetes API server.

### Evidence
In `terraform/aws/eks.tf` (lines 122-125):
```hcl
  vpc_config {
    endpoint_private_access = true
    subnet_ids              = ["${aws_subnet.eks_subnet1.id}", "${aws_subnet.eks_subnet2.id}"]
  }
```
While `endpoint_private_access` was set to `true`, `endpoint_public_access` was omitted, causing it to default to `true` and leaving the public endpoint accessible.

### Remediation
In `terraform/aws/eks.tf`, explicitly set `endpoint_public_access = false` within the `vpc_config` block of the `aws_eks_cluster.eks_cluster` resource. Cluster management traffic will route privately through the configured subnets within the VPC.

### Verification
Run the test with `pytest test_eks_public_endpoint.py` or run `checkov -f terraform/aws/eks.tf --check CKV_AWS_39`. The test validates that `endpoint_public_access = false` is defined within the `vpc_config` block of `aws_eks_cluster.eks_cluster`.