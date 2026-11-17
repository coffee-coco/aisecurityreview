# Run via: pytest test_instances_serial_port.py (or python -m unittest test_instances_serial_port.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))

class TestGoogleComputeInstanceSerialPort(unittest.TestCase):
    def test_serial_port_disabled(self):
        instance_tf_path = REPO_ROOT / "terraform/gcp/instances.tf"
        self.assertTrue(instance_tf_path.exists(), f"Missing file: {instance_tf_path}")

        content = instance_tf_path.read_text()

        # Ensure serial-port-enable is not set to true / "true" / 1
        insecure_pattern = re.compile(r'"?serial-port-enable"?\s*=\s*(?:true|"true"|1|"1")', re.IGNORECASE)
        self.assertIsNone(
            insecure_pattern.search(content),
            "google_compute_instance has serial-port-enable enabled, violating CKV_GCP_35."
        )

        # Ensure serial-port-enable is explicitly set to false
        secure_pattern = re.compile(r'"?serial-port-enable"?\s*=\s*(?:false|"false"|0|"0")', re.IGNORECASE)
        self.assertIsNotNone(
            secure_pattern.search(content),
            "google_compute_instance must have serial-port-enable set to false."
        )

if __name__ == "__main__":
    unittest.main()