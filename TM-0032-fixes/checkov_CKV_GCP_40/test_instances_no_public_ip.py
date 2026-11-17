# Run with: pytest test_instances_no_public_ip.py from repository root or with REPO_ROOT set
import os
import pathlib
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestComputeInstancePublicIP(unittest.TestCase):
    def test_compute_instance_no_access_config(self):
        file_path = REPO_ROOT / "terraform" / "gcp" / "instances.tf"
        self.assertTrue(file_path.exists(), f"File not found: {file_path}")
        content = file_path.read_text(encoding="utf-8")

        start = content.find('resource "google_compute_instance" "server"')
        self.assertNotEqual(start, -1, "Resource google_compute_instance.server not found")

        brace_count = 0
        end = -1
        in_resource = False
        for i in range(start, len(content)):
            if content[i] == "{":
                brace_count += 1
                in_resource = True
            elif content[i] == "}":
                brace_count -= 1
                if in_resource and brace_count == 0:
                    end = i
                    break
        self.assertNotEqual(end, -1, "Could not find closing brace for google_compute_instance.server")
        resource_body = content[start:end]

        self.assertNotIn(
            "access_config",
            resource_body,
            "google_compute_instance.server contains access_config, which assigns a public IP address (CKV_GCP_40)"
        )


if __name__ == "__main__":
    unittest.main()