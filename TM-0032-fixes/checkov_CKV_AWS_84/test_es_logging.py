# Run with: pytest test_es_logging.py (from REPO_ROOT or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestElasticsearchDomainLogging(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(self.tf_file.exists(), f"Target file not found at {self.tf_file}")
        self.content = self.tf_file.read_text()

    def test_elasticsearch_domain_logging_enabled(self):
        """CKV_AWS_84: Ensure Elasticsearch Domain Logging is enabled."""
        # Extract the aws_elasticsearch_domain resource block
        domain_match = re.search(
            r'resource\s+"aws_elasticsearch_domain"\s+"monitoring-framework"\s*\{(.*?)\n\}',
            self.content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            domain_match,
            'Resource "aws_elasticsearch_domain" "monitoring-framework" not found',
        )
        domain_block = domain_match.group(1)

        # Assert that log_publishing_options is present in the resource block
        self.assertIn(
            "log_publishing_options",
            domain_block,
            'Elasticsearch domain "monitoring-framework" does not configure "log_publishing_options" (CKV_AWS_84)',
        )

        # Find all log_publishing_options blocks
        log_blocks = re.findall(
            r'log_publishing_options\s*\{(.*?)\}',
            domain_block,
            re.DOTALL,
        )
        self.assertGreater(
            len(log_blocks),
            0,
            'No log_publishing_options blocks defined in aws_elasticsearch_domain.monitoring-framework',
        )

        # Verify each log_publishing_options specifies cloudwatch_log_group_arn and log_type
        for block in log_blocks:
            self.assertRegex(
                block,
                r'cloudwatch_log_group_arn\s*=',
                'log_publishing_options missing cloudwatch_log_group_arn',
            )
            self.assertRegex(
                block,
                r'log_type\s*=',
                'log_publishing_options missing log_type',
            )
            # If enabled is explicitly specified, verify it is not false
            enabled_match = re.search(r'enabled\s*=\s*(\w+)', block)
            if enabled_match:
                self.assertEqual(
                    enabled_match.group(1).lower(),
                    "true",
                    "log_publishing_options must be enabled",
                )

        # Verify that a CloudWatch log group is declared for publishing logs
        self.assertRegex(
            self.content,
            r'resource\s+"aws_cloudwatch_log_group"\s+',
            'A CloudWatch log group resource must be defined to receive Elasticsearch logs',
        )


if __name__ == "__main__":
    unittest.main()