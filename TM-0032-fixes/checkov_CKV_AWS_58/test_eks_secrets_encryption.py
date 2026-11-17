# Run with: pytest test_eks_secrets_encryption.py from the root of the reviewed repository, or with REPO_ROOT set.
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_block(content: str, pattern: str) -> str | None:
    match = re.search(pattern, content)
    if not match:
        return None
    open_idx = content.find("{", match.end() - 1)
    if open_idx == -1:
        return None
    depth = 1
    idx = open_idx + 1
    while idx < len(content) and depth > 0:
        if content[idx] == "{":
            depth += 1
        elif content[idx] == "}":
            depth -= 1
        idx += 1
    if depth == 0:
        return content[open_idx + 1:idx - 1]
    return None


class TestEKSSecretsEncryption(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform" / "aws" / "eks.tf"
        self.assertTrue(self.tf_file.exists(), f"Terraform file missing: {self.tf_file}")
        self.content = self.tf_file.read_text()

    def test_eks_cluster_has_secrets_encryption_enabled(self):
        # Locate aws_eks_cluster.eks_cluster resource block
        cluster_block = extract_block(
            self.content,
            r'resource\s+("aws_eks_cluster"|aws_eks_cluster)\s+"eks_cluster"\s*\{'
        )
        self.assertIsNotNone(cluster_block, "aws_eks_cluster.eks_cluster block not found")

        # Locate encryption_config block inside aws_eks_cluster
        encryption_config = extract_block(cluster_block, r'encryption_config\s*\{')
        self.assertIsNotNone(
            encryption_config,
            "aws_eks_cluster.eks_cluster lacks encryption_config (CKV_AWS_58)"
        )

        # Ensure resources includes 'secrets'
        self.assertRegex(
            encryption_config,
            r'resources\s*=\s*\[[^\]]*"secrets"[^\]]*\]',
            "encryption_config must include 'secrets' in resources"
        )

        # Ensure provider block defines key_arn
        provider_block = extract_block(encryption_config, r'provider\s*\{')
        self.assertIsNotNone(provider_block, "encryption_config must contain a provider block")
        self.assertRegex(
            provider_block,
            r'key_arn\s*=',
            "provider block must specify key_arn"
        )

        # Ensure KMS key resource is defined in the configuration
        kms_block = extract_block(
            self.content,
            r'resource\s+("aws_kms_key"|aws_kms_key)\s+"eks_kms_key"\s*\{'
        )
        self.assertIsNotNone(kms_block, "aws_kms_key.eks_kms_key resource should be declared")


if __name__ == "__main__":
    unittest.main()