# Run: pytest test_pom_log4j_version.py (from repository root)
import os
import pathlib
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def parse_version_tuple(v: str):
    return tuple(int(x) for x in v.strip().split("."))


class TestLog4jDependencyVersion(unittest.TestCase):
    def test_log4j_version_not_vulnerable(self):
        pom_path = REPO_ROOT / "packages/sub/pom.xml"
        self.assertTrue(pom_path.exists(), f"POM file does not exist: {pom_path}")

        tree = ET.parse(pom_path)
        root = tree.getroot()

        # XML namespace handling
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}

        log4j_version_elem = root.find("m:properties/m:log4j.version", ns)
        if log4j_version_elem is None:
            # Fallback without namespace
            log4j_version_elem = root.find("properties/log4j.version")

        self.assertIsNotNone(
            log4j_version_elem,
            "log4j.version property must be defined in packages/sub/pom.xml",
        )

        version_str = log4j_version_elem.text.strip()
        current_version = parse_version_tuple(version_str)

        # Known vulnerable versions for Log4Shell include 2.0 <= version < 2.17.1
        min_safe_version = (2, 17, 1)
        self.assertGreaterEqual(
            current_version,
            min_safe_version,
            f"log4j.version {version_str} is vulnerable to Log4Shell (CVE-2021-44228/CVE-2021-45046). Must be >= 2.17.1",
        )


if __name__ == "__main__":
    unittest.main()