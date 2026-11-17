# Run: pytest test_es_dedicated_master.py (or python -m unittest test_es_dedicated_master.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestElasticsearchDedicatedMaster(unittest.TestCase):
    def test_dedicated_master_nodes_enabled_and_at_least_three(self):
        config_path = REPO_ROOT / "terraform/aws/es.tf"
        self.assertTrue(config_path.is_file(), f"File not found: {config_path}")
        content = config_path.read_text()

        cluster_config_match = re.search(
            r'cluster_config\s*\{([^}]+)\}',
            content,
            re.MULTILINE | re.DOTALL
        )
        self.assertIsNotNone(cluster_config_match, "cluster_config block not found in es.tf")
        cluster_config = cluster_config_match.group(1)

        enabled_match = re.search(r'dedicated_master_enabled\s*=\s*(true|false)', cluster_config)
        self.assertIsNotNone(enabled_match, "dedicated_master_enabled not found in cluster_config")
        self.assertEqual(
            enabled_match.group(1).lower(),
            "true",
            "dedicated_master_enabled must be true for high availability (CKV_AWS_318)"
        )

        count_match = re.search(r'dedicated_master_count\s*=\s*(\d+)', cluster_config)
        self.assertIsNotNone(count_match, "dedicated_master_count not found in cluster_config")
        master_count = int(count_match.group(1))
        self.assertGreaterEqual(
            master_count,
            3,
            f"dedicated_master_count must be at least 3 for HA quorum, found {master_count}"
        )

if __name__ == "__main__":
    unittest.main()