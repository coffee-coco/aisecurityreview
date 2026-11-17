# Run with: pytest test_cross_service_shared_credentials.py from the root of the reviewed repository, or with REPO_ROOT set.
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestCrossServiceCredentialIsolation(unittest.TestCase):
    def setUp(self):
        self.instance_tf = REPO_ROOT / "terraform/azure/instance.tf"
        self.sql_tf = REPO_ROOT / "terraform/azure/sql.tf"
        self.key_vault_tf = REPO_ROOT / "terraform/azure/key_vault.tf"

        self.assertTrue(self.instance_tf.exists(), f"Missing {self.instance_tf}")
        self.assertTrue(self.sql_tf.exists(), f"Missing {self.sql_tf}")
        self.assertTrue(self.key_vault_tf.exists(), f"Missing {self.key_vault_tf}")

        self.instance_content = self.instance_tf.read_text()
        self.sql_content = self.sql_tf.read_text()
        self.kv_content = self.key_vault_tf.read_text()

    def test_credentials_are_distinct_and_not_shared(self):
        """Verify that Linux VM, Windows VM, MySQL Server, and Key Vault Secret use distinct credentials."""
        linux_match = re.search(
            r'resource\s+azurerm_linux_virtual_machine\s+"linux_machine"\s*\{.*?admin_password\s*=\s*([^\s\n]+)',
            self.instance_content,
            re.DOTALL,
        )
        self.assertIsNotNone(linux_match, "Could not find admin_password for Linux VM")
        linux_pw = linux_match.group(1)

        windows_match = re.search(
            r'resource\s+azurerm_windows_virtual_machine\s+"windows_machine"\s*\{.*?admin_password\s*=\s*([^\s\n]+)',
            self.instance_content,
            re.DOTALL,
        )
        self.assertIsNotNone(windows_match, "Could not find admin_password for Windows VM")
        windows_pw = windows_match.group(1)

        mysql_match = re.search(
            r'resource\s+"azurerm_mysql_server"\s+"example"\s*\{.*?administrator_login_password\s*=\s*([^\s\n]+)',
            self.sql_content,
            re.DOTALL,
        )
        self.assertIsNotNone(mysql_match, "Could not find administrator_login_password for MySQL server")
        mysql_pw = mysql_match.group(1)

        kv_secret_match = re.search(
            r'resource\s+"azurerm_key_vault_secret"\s+"secret"\s*\{.*?value\s*=\s*([^\s\n]+)',
            self.kv_content,
            re.DOTALL,
        )
        self.assertIsNotNone(kv_secret_match, "Could not find value for Key Vault secret")
        kv_secret = kv_secret_match.group(1)

        credentials = [linux_pw, windows_pw, mysql_pw, kv_secret]

        # Assert that the shared insecure credential is not used
        for cred in credentials:
            self.assertNotEqual(
                cred,
                "random_string.password.result",
                f"Resource credential '{cred}' is still referencing shared random_string.password.result",
            )

        # Assert that each resource has its own independent credential source
        self.assertEqual(
            len(set(credentials)),
            4,
            f"Credentials across services must be completely distinct. Found: {credentials}",
        )


if __name__ == "__main__":
    unittest.main()