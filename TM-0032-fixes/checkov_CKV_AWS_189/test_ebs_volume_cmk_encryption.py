# pytest test_ebs_volume_cmk_encryption.py from the repository root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_block(content: str, resource_type: str, resource_name: str) -> str:
    pattern = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    )
    match = pattern.search(content)
    if not match:
        return ""

    start = match.end() - 1
    depth = 0
    for idx in range(start, len(content)):
        char = content[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[match.start(): idx + 1]
    return ""


class TestEBSVolumeCMKEncryption(unittest.TestCase):
    def setUp(self):
        self.tf_file = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(self.tf_file.exists(), f"File not found: {self.tf_file}")
        self.content = self.tf_file.read_text()

    def test_ebs_volume_encrypted_with_customer_managed_key(self):
        ebs_block = extract_resource_block(self.content, "aws_ebs_volume", "web_host_storage")
        self.assertTrue(ebs_block, "Resource aws_ebs_volume.web_host_storage not found in ec2.tf")

        # Check that encrypted is explicitly set to true
        encrypted_match = re.search(r"^\s*encrypted\s*=\s*true\b", ebs_block, re.MULTILINE)
        self.assertIsNotNone(
            encrypted_match,
            "aws_ebs_volume.web_host_storage must have 'encrypted = true'",
        )

        # Check that kms_key_id is explicitly configured
        kms_match = re.search(r"^\s*kms_key_id\s*=\s*([\S]+)", ebs_block, re.MULTILINE)
        self.assertIsNotNone(
            kms_match,
            "aws_ebs_volume.web_host_storage must have 'kms_key_id' configured (CKV_AWS_189)",
        )

        kms_target = kms_match.group(1).strip('"')
        # Ensure it references a customer-managed KMS key resource defined in the config
        key_resource_match = re.search(r"aws_kms_key\.([a-zA-Z0-9_-]+)\.arn", kms_target)
        self.assertIsNotNone(
            key_resource_match,
            f"kms_key_id should reference an aws_kms_key resource ARN, got: {kms_target}",
        )

        key_name = key_resource_match.group(1)
        kms_block = extract_resource_block(self.content, "aws_kms_key", key_name)
        self.assertTrue(
            kms_block,
            f"Referenced aws_kms_key.{key_name} must exist in ec2.tf",
        )


if __name__ == "__main__":
    unittest.main()