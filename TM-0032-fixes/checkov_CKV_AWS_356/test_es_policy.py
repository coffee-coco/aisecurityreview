# Run with: pytest test_es_policy.py (from repository root, or set REPO_ROOT)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestElasticsearchIAMPolicy(unittest.TestCase):
    def test_policy_document_does_not_use_wildcard_resource(self):
        target_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(target_file.exists(), f"{target_file} does not exist")
        content = target_file.read_text()

        # Extract data aws_iam_policy_document "policy" block
        policy_match = re.search(
            r'data\s+"?aws_iam_policy_document"?\s+"policy"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(policy_match, "aws_iam_policy_document.policy block not found")
        policy_body = policy_match.group(1)

        # Ensure wildcard '*' is not specified as a resource
        self.assertNotRegex(
            policy_body,
            r'resources\s*=\s*\[\s*"\*"\s*\]',
            "aws_iam_policy_document.policy allows wildcard '*' as statement resource (violates CKV_AWS_356)",
        )

        # Ensure the resource is scoped to the specific elasticsearch domain
        self.assertIn(
            "aws_elasticsearch_domain.monitoring-framework.arn",
            policy_body,
            "aws_iam_policy_document.policy must scope resources to aws_elasticsearch_domain.monitoring-framework.arn",
        )


if __name__ == "__main__":
    unittest.main()