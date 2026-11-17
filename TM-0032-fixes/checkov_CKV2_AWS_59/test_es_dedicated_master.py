# Run using: pytest test_es_dedicated_master.py
# or: python -m unittest test_es_dedicated_master.py

import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestElasticsearchDedicatedMaster(unittest.TestCase):
    def test_dedicated_master_enabled(self):
        tf_file = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(tf_file.exists(), f"{tf_file} does not exist")

        content = tf_file.read_text()

        # Locate aws_elasticsearch_domain block
        domain_match = re.search(
            r'resource\s+"aws_elasticsearch_domain"\s+"monitoring-framework"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            domain_match,
            "Could not find resource aws_elasticsearch_domain 'monitoring-framework' in es.tf",
        )

        domain_block = domain_match.group(1)

        # Locate cluster_config block inside the domain resource
        cluster_config_match = re.search(
            r'cluster_config\s*\{(.*?)\}',
            domain_block,
            re.DOTALL,
        )
        self.assertIsNotNone(
            cluster_config_match,
            "Could not find cluster_config block in monitoring-framework",
        )

        cluster_config = cluster_config_match.group(1)

        # Check dedicated_master_enabled setting
        dedicated_master_match = re.search(
            r'dedicated_master_enabled\s*=\s*(true|false)',
            cluster_config,
            re.IGNORECASE,
        )
        self.assertIsNotNone(
            dedicated_master_match,
            "dedicated_master_enabled is not specified in cluster_config",
        )

        setting_value = dedicated_master_match.group(1).lower()
        self.assertEqual(
            setting_value,
            "true",
            f"ElasticSearch domain 'monitoring-framework' has dedicated_master_enabled = {setting_value}; expected 'true'",
        )


if __name__ == "__main__":
    unittest.main()