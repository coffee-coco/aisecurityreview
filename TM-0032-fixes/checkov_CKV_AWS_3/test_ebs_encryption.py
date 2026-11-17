# Run using: pytest test_ebs_encryption.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_block(tf_code: str, res_type: str, res_name: str) -> str:
    pattern = rf'resource\s+"{res_type}"\s+"{res_name}"\s*\{{'
    match = re.search(pattern, tf_code)
    if not match:
        return ""
    start = match.end()
    depth = 1
    idx = start
    while idx < len(tf_code) and depth > 0:
        if tf_code[idx] == "{":
            depth += 1
        elif tf_code[idx] == "}":
            depth -= 1
        idx += 1
    return tf_code[start : idx - 1]


class TestEbsEncryption(unittest.TestCase):
    def test_web_host_storage_ebs_encrypted(self):
        ec2_tf = REPO_ROOT / "terraform/aws/ec2.tf"
        self.assertTrue(ec2_tf.is_file(), f"{ec2_tf} not found")
        content = ec2_tf.read_text()

        block = extract_resource_block(content, "aws_ebs_volume", "web_host_storage")
        self.assertTrue(block, "aws_ebs_volume.web_host_storage resource not found in ec2.tf")

        # Verify that encrypted is set to true on an active (uncommented) line
        has_encrypted = any(
            re.match(r"^\s*encrypted\s*=\s*true\b", line)
            for line in block.splitlines()
        )
        self.assertTrue(
            has_encrypted,
            "aws_ebs_volume.web_host_storage must have 'encrypted = true' enabled",
        )


if __name__ == "__main__":
    unittest.main()