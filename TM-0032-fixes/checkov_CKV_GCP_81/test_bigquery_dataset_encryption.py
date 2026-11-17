# Run with: pytest test_bigquery_dataset_encryption.py (or REPO_ROOT=. python -m unittest test_bigquery_dataset_encryption.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resource_block(content: str, resource_type: str, resource_name: str) -> str:
    header = f'resource "{resource_type}" "{resource_name}"'
    start_pos = content.find(header)
    if start_pos == -1:
        return ""
    open_brace_pos = content.find("{", start_pos)
    if open_brace_pos == -1:
        return ""
    depth = 0
    for i in range(open_brace_pos, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[open_brace_pos : i + 1]
    return ""


class TestBigQueryDatasetEncryption(unittest.TestCase):
    def test_bigquery_dataset_has_csek_encryption(self):
        target_file = REPO_ROOT / "terraform" / "gcp" / "big_data.tf"
        self.assertTrue(target_file.exists(), f"{target_file} does not exist")
        content = target_file.read_text()

        dataset_block = extract_resource_block(content, "google_bigquery_dataset", "dataset")
        self.assertTrue(
            dataset_block,
            "Could not find google_bigquery_dataset.dataset resource in big_data.tf",
        )

        self.assertIn(
            "default_encryption_configuration",
            dataset_block,
            "google_bigquery_dataset.dataset lacks a default_encryption_configuration block (CKV_GCP_81)",
        )
        self.assertRegex(
            dataset_block,
            r"kms_key_name\s*=",
            "default_encryption_configuration must specify kms_key_name",
        )


if __name__ == "__main__":
    unittest.main()