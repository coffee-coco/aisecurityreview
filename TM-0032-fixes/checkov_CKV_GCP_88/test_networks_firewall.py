# Run with: pytest test_networks_firewall.py (from repo root or with REPO_ROOT set)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestGoogleComputeFirewallMysqlAccess(unittest.TestCase):
    def test_firewall_ingress_disallows_unrestricted_mysql(self):
        """Verify google_compute_firewall.allow_all does not permit unrestricted (0.0.0.0/0) MySQL (3306) access."""
        tf_file = REPO_ROOT / "terraform/gcp/networks.tf"
        self.assertTrue(tf_file.is_file(), f"File not found: {tf_file}")
        content = tf_file.read_text(encoding="utf-8")

        match = re.search(r'resource\s+"google_compute_firewall"\s+"allow_all"\s*\{', content)
        self.assertIsNotNone(match, "Resource google_compute_firewall.allow_all not found in networks.tf")

        # Extract the resource block using brace matching
        start_idx = match.end()
        depth = 1
        end_idx = start_idx
        for idx in range(start_idx, len(content)):
            if content[idx] == "{":
                depth += 1
            elif content[idx] == "}":
                depth -= 1
                if depth == 0:
                    end_idx = idx
                    break
        block = content[start_idx:end_idx]

        # Extract source_ranges
        sr_match = re.search(r"source_ranges\s*=\s*\[(.*?)\]", block, re.DOTALL)
        self.assertIsNotNone(sr_match, "source_ranges attribute not found in google_compute_firewall.allow_all")
        source_ranges = [
            s.strip().strip('"').strip("'")
            for s in sr_match.group(1).split(",")
            if s.strip()
        ]

        # Extract allowed ports
        ports_match = re.search(r"ports\s*=\s*\[(.*?)\]", block, re.DOTALL)
        if ports_match:
            ports = [
                p.strip().strip('"').strip("'")
                for p in ports_match.group(1).split(",")
                if p.strip()
            ]
        else:
            ports = []

        mysql_port = 3306
        port_3306_allowed = False
        if not ports:
            port_3306_allowed = True
        else:
            for p in ports:
                if "-" in p:
                    parts = p.split("-")
                    if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                        low, high = int(parts[0].strip()), int(parts[1].strip())
                        if low <= mysql_port <= high:
                            port_3306_allowed = True
                            break
                elif p.isdigit() and int(p) == mysql_port:
                    port_3306_allowed = True
                    break

        unrestricted_cidrs = {"0.0.0.0/0", "::/0", "/0"}
        has_unrestricted_source = any(sr in unrestricted_cidrs for sr in source_ranges)
        allows_unrestricted_mysql = has_unrestricted_source and port_3306_allowed

        self.assertFalse(
            allows_unrestricted_mysql,
            f"google_compute_firewall.allow_all allows unrestricted access to MySQL (port 3306): "
            f"source_ranges={source_ranges}, ports={ports}",
        )


if __name__ == "__main__":
    unittest.main()