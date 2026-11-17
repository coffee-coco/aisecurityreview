# Run via: pytest test_postgresql_infrastructure_encryption.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestPostgreSqlInfrastructureEncryption(unittest.TestCase):
    def test_azurerm_postgresql_server_enables_infrastructure_encryption(self):
        sql_tf_path = REPO_ROOT / "terraform" / "azure" / "sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"{sql_tf_path} does not exist")

        content = sql_tf_path.read_text()

        # Find the azurerm_postgresql_server resource block
        block_match = re.search(
            r'resource\s+"azurerm_postgresql_server"\s+"example"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            block_match,
            "Could not find 'resource \"azurerm_postgresql_server\" \"example\"' block",
        )

        server_block = block_match.group(1)

        # Check that infrastructure_encryption_enabled is explicitly set to true
        match = re.search(
            r'infrastructure_encryption_enabled\s*=\s*(true|false)',
            server_block,
            re.IGNORECASE,
        )
        self.assertIsNotNone(
            match,
            "azurerm_postgresql_server.example must define 'infrastructure_encryption_enabled = true'",
        )
        self.assertEqual(
            match.group(1).lower(),
            "true",
            f"infrastructure_encryption_enabled should be 'true', got: {match.group(1)}",
        )


if __name__ == "__main__":
    unittest.main()