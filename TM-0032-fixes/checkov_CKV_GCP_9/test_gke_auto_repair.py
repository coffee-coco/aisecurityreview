# Run with: pytest test_gke_auto_repair.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_block(content: str, block_header: str) -> str:
    start_idx = content.find(block_header)
    if start_idx == -1:
        return ""
    brace_start = content.find("{", start_idx)
    if brace_start == -1:
        return ""
    depth = 0
    for idx in range(brace_start, len(content)):
        char = content[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[brace_start + 1 : idx]
    return ""


class TestGKENodePoolAutoRepair(unittest.TestCase):
    def test_custom_node_pool_has_auto_repair_enabled(self):
        tf_path = REPO_ROOT / "terraform/gcp/gke.tf"
        self.assertTrue(tf_path.is_file(), f"File not found: {tf_path}")

        content = tf_path.read_text()
        body = extract_block(
            content, 'resource "google_container_node_pool" "custom_node_pool"'
        )
        self.assertTrue(
            body,
            "Could not find resource 'google_container_node_pool.custom_node_pool'",
        )

        mgmt_pattern = re.compile(
            r'management\s*\{[^}]*auto_repair\s*=\s*true[^}]*\}',
            re.DOTALL,
        )
        self.assertIsNotNone(
            mgmt_pattern.search(body),
            "Resource 'google_container_node_pool.custom_node_pool' must have 'management' block with 'auto_repair = true'",
        )


if __name__ == "__main__":
    unittest.main()