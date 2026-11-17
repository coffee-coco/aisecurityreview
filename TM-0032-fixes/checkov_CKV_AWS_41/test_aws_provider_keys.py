# Run via: pytest test_aws_provider_keys.py (or REPO_ROOT=/path/to/repo pytest test_aws_provider_keys.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestAWSProviderCredentials(unittest.TestCase):
    def test_no_hardcoded_aws_keys_in_provider(self):
        providers_file = REPO_ROOT / "terraform" / "aws" / "providers.tf"
        self.assertTrue(providers_file.exists(), f"{providers_file} does not exist")

        content = providers_file.read_text()

        # Assert no plain text access_key or secret_key defined in provider blocks
        access_key_match = re.search(r"^\s*access_key\s*=\s*.*$", content, re.MULTILINE)
        secret_key_match = re.search(r"^\s*secret_key\s*=\s*.*$", content, re.MULTILINE)

        self.assertIsNone(
            access_key_match,
            f"Found hardcoded access_key in providers.tf: {access_key_match.group(0) if access_key_match else ''}",
        )
        self.assertIsNone(
            secret_key_match,
            f"Found hardcoded secret_key in providers.tf: {secret_key_match.group(0) if secret_key_match else ''}",
        )


if __name__ == "__main__":
    unittest.main()