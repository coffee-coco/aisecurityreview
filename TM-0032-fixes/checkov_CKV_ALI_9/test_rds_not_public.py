# Run: pytest test_rds_not_public.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestRDSNotPublic(unittest.TestCase):
    def test_alicloud_db_instance_not_public(self):
        rds_file = REPO_ROOT / "terraform/alicloud/rds.tf"
        self.assertTrue(rds_file.is_file(), f"File not found: {rds_file}")

        content = rds_file.read_text()

        # Locate resource "alicloud_db_instance" "seeme"
        resource_match = re.search(
            r'resource\s+"alicloud_db_instance"\s+"seeme"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(resource_match, "alicloud_db_instance.seeme block not found")
        resource_body = resource_match.group(1)

        # Extract security_ips list
        ips_match = re.search(r'security_ips\s*=\s*\[(.*?)\]', resource_body, re.DOTALL)
        self.assertIsNotNone(ips_match, "security_ips block not found in alicloud_db_instance.seeme")
        ips_block = ips_match.group(1)

        # Parse individual IP strings
        ips = [ip.strip().strip('"') for ip in ips_block.split(",") if ip.strip().strip('"')]

        disallowed_cidrs = {"0.0.0.0", "0.0.0.0/0", "%"}
        for ip in ips:
            self.assertNotIn(
                ip,
                disallowed_cidrs,
                f"Public IP '{ip}' found in security_ips whitelist for alicloud_db_instance.seeme",
            )


if __name__ == "__main__":
    unittest.main()