# Run with: pytest test_big_data_public_ip.py (or python -m unittest test_big_data_public_ip.py) from the repo root or with REPO_ROOT set
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_block(text: str, header_pattern: str) -> str:
    match = re.search(header_pattern, text)
    if not match:
        return ""
    start = match.end()
    depth = 1
    idx = start
    while idx < len(text) and depth > 0:
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
        idx += 1
    return text[start : idx - 1]


class TestCloudSqlPublicIp(unittest.TestCase):
    def test_master_instance_public_ip_disabled(self):
        config_path = REPO_ROOT / "terraform" / "gcp" / "big_data.tf"
        self.assertTrue(config_path.exists(), f"Configuration file does not exist: {config_path}")
        content = config_path.read_text(encoding="utf-8")

        instance_block = extract_block(
            content,
            r'resource\s+"google_sql_database_instance"\s+"master_instance"\s*\{',
        )
        self.assertTrue(
            instance_block,
            "Could not find 'google_sql_database_instance.master_instance' resource block.",
        )

        ip_config_block = extract_block(instance_block, r'ip_configuration\s*\{')
        self.assertTrue(
            ip_config_block,
            "Could not find 'ip_configuration' block in 'master_instance'.",
        )

        ipv4_match = re.search(r'ipv4_enabled\s*=\s*(true|false)', ip_config_block)
        self.assertIsNotNone(
            ipv4_match,
            "'ipv4_enabled' setting was not explicitly configured in 'ip_configuration'.",
        )
        self.assertEqual(
            ipv4_match.group(1).lower(),
            "false",
            f"Expected ipv4_enabled to be false to avoid assigning a public IP (CKV_GCP_60), got: {ipv4_match.group(1)}",
        )


if __name__ == "__main__":
    unittest.main()