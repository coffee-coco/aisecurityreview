# Run with: pytest test_aks_logging.py (or python -m unittest test_aks_logging.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAksLoggingConfiguration(unittest.TestCase):
    def test_aks_oms_agent_logging_enabled(self):
        aks_tf_path = REPO_ROOT / "terraform/azure/aks.tf"
        self.assertTrue(aks_tf_path.exists(), f"Target file {aks_tf_path} does not exist")

        content = aks_tf_path.read_text()

        # Locate oms_agent block inside addon_profile
        oms_agent_match = re.search(
            r"oms_agent\s*\{[^}]*enabled\s*=\s*([a-zA-Z0-9_"]+)[^}]*\}",
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            oms_agent_match,
            "oms_agent block with enabled attribute not found in terraform/azure/aks.tf",
        )

        enabled_val = oms_agent_match.group(1).strip().lower()
        self.assertEqual(
            enabled_val,
            "true",
            f"Expected oms_agent.enabled to be 'true' for Azure Monitor logging (CKV_AZURE_4), but got '{enabled_val}'",
        )


if __name__ == "__main__":
    unittest.main()