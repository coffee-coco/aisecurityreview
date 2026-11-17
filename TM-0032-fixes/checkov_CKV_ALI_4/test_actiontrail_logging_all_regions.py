# Run with: pytest test_actiontrail_logging_all_regions.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestActionTrailLoggingAllRegions(unittest.TestCase):
    def test_trail_logging_all_regions(self):
        trail_file = REPO_ROOT / "terraform/alicloud/trail.tf"
        self.assertTrue(trail_file.is_file(), f"File not found: {trail_file}")

        content = trail_file.read_text(encoding="utf-8")

        # Find alicloud_actiontrail_trail resource blocks
        pattern = re.compile(
            r'resource\s+"alicloud_actiontrail_trail"\s+"[^"]+"\s*\{([^}]*)\}',
            re.MULTILINE | re.DOTALL,
        )
        matches = pattern.findall(content)
        self.assertTrue(matches, "No alicloud_actiontrail_trail resource found")

        for block in matches:
            region_match = re.search(r'trail_region\s*=\s*"([^"]+)"', block)
            self.assertIsNotNone(
                region_match, "trail_region attribute not specified in trail block"
            )
            trail_region = region_match.group(1)
            self.assertEqual(
                trail_region,
                "All",
                f"Action Trail must be configured to log for all regions ('All'), found: '{trail_region}'",
            )


if __name__ == "__main__":
    unittest.main()