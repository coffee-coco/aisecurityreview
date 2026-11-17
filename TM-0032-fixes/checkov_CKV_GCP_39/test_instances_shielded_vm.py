# Run with: pytest test_instances_shielded_vm.py (or python -m unittest test_instances_shielded_vm.py) from repository root
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestShieldedVMEnabled(unittest.TestCase):
    def setUp(self):
        self.instance_file = REPO_ROOT / "terraform/gcp/instances.tf"
        self.assertTrue(self.instance_file.is_file(), f"File not found: {self.instance_file}")
        self.content = self.instance_file.read_text()

    def _extract_resource_block(self, resource_type: str, resource_name: str) -> str:
        pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
        match = re.search(pattern, self.content)
        self.assertIsNotNone(match, f"Resource {resource_type}.{resource_name} not found in {self.instance_file}")
        start_pos = match.end()
        brace_count = 1
        end_pos = start_pos
        while end_pos < len(self.content) and brace_count > 0:
            if self.content[end_pos] == "{":
                brace_count += 1
            elif self.content[end_pos] == "}":
                brace_count -= 1
            end_pos += 1
        return self.content[start_pos : end_pos - 1]

    def test_compute_instance_has_shielded_vm_enabled(self):
        server_block = self._extract_resource_block("google_compute_instance", "server")

        # Assert shielded_instance_config block is defined
        shielded_block_match = re.search(r"shielded_instance_config\s*\{([^}]+)\}", server_block)
        self.assertIsNotNone(
            shielded_block_match,
            "google_compute_instance.server is missing shielded_instance_config block (CKV_GCP_39)",
        )

        shielded_config = shielded_block_match.group(1)

        # Check secure boot
        secure_boot_match = re.search(r"enable_secure_boot\s*=\s*(true|false)", shielded_config)
        self.assertIsNotNone(secure_boot_match, "enable_secure_boot is not configured in shielded_instance_config")
        self.assertEqual(
            secure_boot_match.group(1),
            "true",
            "enable_secure_boot must be true for Shielded VM",
        )

        # Check vTPM
        vtpm_match = re.search(r"enable_vtpm\s*=\s*(true|false)", shielded_config)
        self.assertIsNotNone(vtpm_match, "enable_vtpm is not configured in shielded_instance_config")
        self.assertEqual(vtpm_match.group(1), "true", "enable_vtpm must be true for Shielded VM")

        # Check integrity monitoring
        integrity_match = re.search(r"enable_integrity_monitoring\s*=\s*(true|false)", shielded_config)
        self.assertIsNotNone(
            integrity_match,
            "enable_integrity_monitoring is not configured in shielded_instance_config",
        )
        self.assertEqual(
            integrity_match.group(1),
            "true",
            "enable_integrity_monitoring must be true for Shielded VM",
        )


if __name__ == "__main__":
    unittest.main()