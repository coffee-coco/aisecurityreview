# pytest test_es_fine_grained_access_control.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestElasticsearchFineGrainedAccessControl(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(self.tf_file.exists(), f"File not found: {self.tf_file}")
        self.content = self.tf_file.read_text(encoding="utf-8")

    def test_fine_grained_access_control_enabled(self):
        match = re.search(
            r'resource\s+"aws_elasticsearch_domain"\s+"monitoring-framework"\s*\{(.*?)\n^\}',
            self.content,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, 'Resource aws_elasticsearch_domain "monitoring-framework" not found')
        resource_body = match.group(1)

        aso_match = re.search(
            r'advanced_security_options\s*\{(.*?)\}',
            resource_body,
            re.DOTALL,
        )
        self.assertIsNotNone(
            aso_match,
            "aws_elasticsearch_domain.monitoring-framework must configure advanced_security_options (CKV2_AWS_52)",
        )

        aso_body = aso_match.group(1)
        enabled_match = re.search(r'enabled\s*=\s*true\b', aso_body)
        self.assertIsNotNone(
            enabled_match,
            "advanced_security_options must have enabled = true (CKV2_AWS_52)",
        )


if __name__ == "__main__":
    unittest.main()