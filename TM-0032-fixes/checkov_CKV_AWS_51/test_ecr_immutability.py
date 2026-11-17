# Run: pytest test_ecr_immutability.py
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestECRImageTagMutability(unittest.TestCase):
    def test_ecr_tag_mutability_is_immutable(self):
        ecr_file = REPO_ROOT / "terraform/aws/ecr.tf"
        self.assertTrue(ecr_file.exists(), f"{ecr_file} does not exist")

        content = ecr_file.read_text()

        # Search for aws_ecr_repository resource block and verify image_tag_mutability is IMMUTABLE
        pattern = re.compile(
            r'resource\s+"aws_ecr_repository"\s+"repository"\s*\{[^}]*image_tag_mutability\s*=\s*"([^"]+)"',
            re.DOTALL,
        )
        match = pattern.search(content)
        self.assertIsNotNone(
            match,
            "Could not find aws_ecr_repository.repository with image_tag_mutability configured",
        )
        mutability_val = match.group(1)
        self.assertEqual(
            mutability_val,
            "IMMUTABLE",
            f"Expected image_tag_mutability to be 'IMMUTABLE', but found '{mutability_val}'",
        )


if __name__ == "__main__":
    unittest.main()