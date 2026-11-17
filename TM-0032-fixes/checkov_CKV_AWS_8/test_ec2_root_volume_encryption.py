# Run with: pytest test_ec2_root_volume_encryption.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestEC2ServerEncryption(unittest.TestCase):
    def _extract_resource_block(self, content: str, resource_type: str, resource_name: str) -> str:
        pattern = rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*\{{'
        match = re.search(pattern, content)
        if not match:
            self.fail(f"Resource {resource_type}.{resource_name} not found")
        start = match.end() - 1
        brace_count = 0
        end = start
        for i in range(start, len(content)):
            if content[i] == "{":
                brace_count += 1
            elif content[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        return content[start:end]

    def test_db_app_root_block_device_encrypted(self):
        db_app_path = REPO_ROOT / "terraform" / "aws" / "db-app.tf"
        self.assertTrue(db_app_path.exists(), f"File not found: {db_app_path}")
        content = db_app_path.read_text()
        block = self._extract_resource_block(content, "aws_instance", "db_app")
        self.assertRegex(
            block,
            r"root_block_device\s*\{[^}]*encrypted\s*=\s*true",
            "aws_instance.db_app must configure root_block_device with encrypted = true to remediate CKV_AWS_8",
        )

    def test_web_host_root_block_device_encrypted(self):
        ec2_path = REPO_ROOT / "terraform" / "aws" / "ec2.tf"
        self.assertTrue(ec2_path.exists(), f"File not found: {ec2_path}")
        content = ec2_path.read_text()
        block = self._extract_resource_block(content, "aws_instance", "web_host")
        self.assertRegex(
            block,
            r"root_block_device\s*\{[^}]*encrypted\s*=\s*true",
            "aws_instance.web_host must configure root_block_device with encrypted = true to remediate CKV_AWS_8",
        )


if __name__ == "__main__":
    unittest.main()