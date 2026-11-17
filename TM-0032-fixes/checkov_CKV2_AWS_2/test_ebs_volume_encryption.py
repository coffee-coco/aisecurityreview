# Run using: pytest test_ebs_volume_encryption.py (from repository root, or set REPO_ROOT)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestEbsVolumeEncryption(unittest.TestCase):
    def test_web_host_storage_volume_is_encrypted(self):
        ec2_tf_path = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_tf_path.exists(), f"File not found: {ec2_tf_path}")

        content = ec2_tf_path.read_text()

        # Extract resource "aws_ebs_volume" "web_host_storage" block
        block_match = re.search(
            r'resource\s+"aws_ebs_volume"\s+"web_host_storage"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
            content,
            re.MULTILINE,
        )
        self.assertIsNotNone(block_match, "aws_ebs_volume.web_host_storage resource not found")
        block_body = block_match.group(1)

        # Strip line comments before checking for the encrypted attribute
        active_lines = [
            line.split("#")[0].strip()
            for line in block_body.splitlines()
            if not line.strip().startswith("#")
        ]
        active_content = "\n".join(active_lines)

        # Verify that encrypted is explicitly set to true
        self.assertRegex(
            active_content,
            r'\bencrypted\s*=\s*true\b',
            "aws_ebs_volume.web_host_storage must have 'encrypted = true' configured",
        )


if __name__ == "__main__":
    unittest.main()