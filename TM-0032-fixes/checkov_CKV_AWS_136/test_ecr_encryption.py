# Run with: pytest <test_filename> or python -m unittest <test_filename>
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestECREncryption(unittest.TestCase):
    def test_ecr_repository_kms_encryption(self):
        ecr_file = REPO_ROOT / "terraform/aws/ecr.tf"
        self.assertTrue(ecr_file.exists(), f"ECR Terraform file not found: {ecr_file}")
        content = ecr_file.read_text()

        # Locate aws_ecr_repository.repository block
        repo_match = re.search(
            r'resource\s+(?:"aws_ecr_repository"|aws_ecr_repository)\s+"repository"\s*\{(?P<body>.*?)^\}',
            content,
            flags=re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(repo_match, "aws_ecr_repository.repository resource block not found")
        body = repo_match.group("body")

        # Check for encryption_configuration block
        enc_match = re.search(
            r'encryption_configuration\s*\{(?P<enc_body>[^}]+)\}',
            body,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(
            enc_match,
            "aws_ecr_repository.repository is missing the 'encryption_configuration' block (CKV_AWS_136)",
        )

        enc_body = enc_match.group("enc_body")
        kms_match = re.search(r'encryption_type\s*=\s*"KMS"', enc_body)
        self.assertIsNotNone(
            kms_match,
            "encryption_configuration must have encryption_type set to 'KMS'",
        )


if __name__ == "__main__":
    unittest.main()