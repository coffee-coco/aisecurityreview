# Run via: pytest test_instances_ssh_keys.py (or python -m unittest test_instances_ssh_keys.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestBlockProjectWideSSHKeys(unittest.TestCase):
    def test_block_project_wide_ssh_keys_enabled(self):
        config_path = REPO_ROOT / "terraform/gcp/instances.tf"
        self.assertTrue(config_path.exists(), f"{config_path} does not exist")

        content = config_path.read_text()

        # Locate resource "google_compute_instance" "server"
        match = re.search(
            r'resource\s+"google_compute_instance"\s+"server"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "google_compute_instance.server resource not found")
        instance_body = match.group(1)

        # Extract metadata block
        metadata_match = re.search(r'metadata\s*=\s*\{(.*?)\}', instance_body, re.DOTALL)
        self.assertIsNotNone(metadata_match, "metadata block not found in server instance")
        metadata_body = metadata_match.group(1)

        # Check block-project-ssh-keys setting
        key_match = re.search(r'block-project-ssh-keys\s*=\s*(["a-zA-Z0-9_-]+)', metadata_body)
        self.assertIsNotNone(key_match, "block-project-ssh-keys is not configured in metadata")

        value = key_match.group(1).strip('"\'')
        self.assertEqual(
            value.lower(),
            "true",
            f"Expected block-project-ssh-keys to be 'true', got: {value}",
        )


if __name__ == "__main__":
    unittest.main()