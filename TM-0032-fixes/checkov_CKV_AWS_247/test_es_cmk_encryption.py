# Run via: pytest test_es_cmk_encryption.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestElasticsearchCMKEncryption(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(self.tf_file.is_file(), f"File not found: {self.tf_file}")
        self.content = self.tf_file.read_text()

    def test_elasticsearch_domain_has_cmk_encryption(self):
        """Verify that aws_elasticsearch_domain.monitoring-framework has an encrypt_at_rest block configured with a CMK."""
        # Find the aws_elasticsearch_domain resource block
        domain_match = re.search(
            r'resource\s+"aws_elasticsearch_domain"\s+"monitoring-framework"\s*\{(.*?)\n\}',
            self.content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            domain_match,
            "Resource aws_elasticsearch_domain.monitoring-framework not found",
        )
        domain_body = domain_match.group(1)

        # Find encrypt_at_rest block inside the domain resource
        encrypt_match = re.search(
            r'encrypt_at_rest\s*\{(.*?)\}',
            domain_body,
            re.DOTALL,
        )
        self.assertIsNotNone(
            encrypt_match,
            "encrypt_at_rest block not found in aws_elasticsearch_domain.monitoring-framework",
        )
        encrypt_body = encrypt_match.group(1)

        # Assert enabled = true
        self.assertRegex(
            encrypt_body,
            r'enabled\s*=\s*true',
            "encrypt_at_rest must have 'enabled = true'",
        )

        # Assert kms_key_id is configured with a CMK reference
        kms_match = re.search(r'kms_key_id\s*=\s*([^\n]+)', encrypt_body)
        self.assertIsNotNone(
            kms_match,
            "encrypt_at_rest must configure kms_key_id with a Customer Managed Key (CMK)",
        )
        kms_key_value = kms_match.group(1).strip().strip('"')
        self.assertTrue(
            len(kms_key_value) > 0,
            "kms_key_id must not be empty",
        )

        # Assert that the referenced KMS key resource is defined in the configuration
        kms_resource_match = re.search(
            r'resource\s+"aws_kms_key"\s+"([^"]+)"',
            self.content,
        )
        self.assertIsNotNone(
            kms_resource_match,
            "An aws_kms_key resource must be defined for customer-managed encryption",
        )


if __name__ == "__main__":
    unittest.main()