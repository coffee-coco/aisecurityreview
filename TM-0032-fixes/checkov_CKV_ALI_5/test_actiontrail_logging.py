# Run: pytest test_actiontrail_logging.py (or python -m unittest test_actiontrail_logging.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestActionTrailLogging(unittest.TestCase):
    def test_action_trail_logs_all_events(self):
        trail_path = REPO_ROOT / "terraform/alicloud/trail.tf"
        self.assertTrue(trail_path.is_file(), f"{trail_path} does not exist")

        content = trail_path.read_text(encoding="utf-8")
        trail_match = re.search(
            r'resource\s+"alicloud_actiontrail_trail"\s+"[^"]+"\s*{(.*?)}',
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(
            trail_match, "alicloud_actiontrail_trail resource not found"
        )

        trail_block = trail_match.group(1)
        event_rw_match = re.search(r'event_rw\s*=\s*"([^"]+)"', trail_block)
        self.assertIsNotNone(
            event_rw_match,
            "event_rw attribute missing in alicloud_actiontrail_trail resource",
        )

        event_rw_val = event_rw_match.group(1)
        self.assertEqual(
            event_rw_val,
            "All",
            f"ActionTrail should log all events, but event_rw is '{event_rw_val}'",
        )


if __name__ == "__main__":
    unittest.main()