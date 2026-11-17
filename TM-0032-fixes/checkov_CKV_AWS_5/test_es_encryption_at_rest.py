# Run via: pytest test_es_encryption_at_rest.py (or python -m unittest test_es_encryption_at_rest.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestElasticsearchEncryptionAtRest(unittest.TestCase):
    def test_elasticsearch_domain_encrypt_at_rest_enabled(self):
        target_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(target_file.exists(), f"Configuration file {target_file} does not exist")

        content = target_file.read_text()

        # Match the aws_elasticsearch_domain resource block
        domain_match = re.search(
            r'resource\s+"aws_elasticsearch_domain"\s+"monitoring-framework"\s*\{(?P<body>[\s\S]*?)(?:\n\}\n|\Z)',
            content,
        )
        self.assertIsNotNone(
            domain_match, "Resource aws_elasticsearch_domain.monitoring-framework not found in es.tf"
        )

        body = domain_match.group("body")

        # Verify that encrypt_at_rest block exists and enabled is true
        encrypt_match = re.search(
            r'encrypt_at_rest\s*\{[^}]*enabled\s*=\s*true[^}]*\}',
            body,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            encrypt_match,
            "aws_elasticsearch_domain.monitoring-framework must have an encrypt_at_rest block with enabled = true",
        )


if __name__ == "__main__":
    unittest.main()