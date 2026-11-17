# Run with pytest test_ecr_scan_on_push.py from repo root or with REPO_ROOT set
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestECRScanOnPush(unittest.TestCase):
    def test_ecr_scan_on_push_enabled(self):
        ecr_file = REPO_ROOT / "terraform/aws/ecr.tf"
        self.assertTrue(ecr_file.is_file(), f"File not found: {ecr_file}")
        content = ecr_file.read_text()

        # Match aws_ecr_repository block
        match = re.search(r'resource\s+aws_ecr_repository\s+"repository"\s*\{(.*?)\n\}', content, re.DOTALL)
        self.assertIsNotNone(match, "aws_ecr_repository \"repository\" resource block not found")
        repo_block = match.group(1)

        # Verify image_scanning_configuration block with scan_on_push = true exists
        scanning_match = re.search(r'image_scanning_configuration\s*\{\s*scan_on_push\s*=\s*true\s*\}', repo_block)
        self.assertIsNotNone(
            scanning_match,
            "ECR repository must have image_scanning_configuration { scan_on_push = true } enabled (CKV_AWS_163)",
        )


if __name__ == "__main__":
    unittest.main()