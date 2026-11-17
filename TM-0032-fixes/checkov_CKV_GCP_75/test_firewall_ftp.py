# Run with: pytest test_firewall_ftp.py (or REPO_ROOT=/path/to/repo pytest test_firewall_ftp.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def is_port_in_range(target_port: int, port_spec: str) -> bool:
    port_spec = port_spec.strip().strip('"').strip("'")
    if "-" in port_spec:
        start_str, end_str = port_spec.split("-", 1)
        try:
            start, end = int(start_str), int(end_str)
            return start <= target_port <= end
        except ValueError:
            return False
    try:
        return int(port_spec) == target_port
    except ValueError:
        return False


class TestGoogleComputeFirewallFTP(unittest.TestCase):
    def test_firewall_does_not_allow_unrestricted_ftp(self):
        config_path = REPO_ROOT / "terraform/gcp/networks.tf"
        self.assertTrue(config_path.is_file(), f"File not found: {config_path}")

        content = config_path.read_text()

        # Extract google_compute_firewall resource blocks
        firewall_blocks = re.findall(
            r'resource\s+"google_compute_firewall"\s+"([^"]+)"\s*\{(.*?)\n\}',
            content,
            re.DOTALL,
        )
        self.assertTrue(firewall_blocks, "No google_compute_firewall resource found")

        for name, block in firewall_blocks:
            # Extract source_ranges
            source_ranges_match = re.search(r'source_ranges\s*=\s*\[([^\]]*)\]', block)
            if not source_ranges_match:
                continue

            raw_sources = source_ranges_match.group(1)
            sources = [
                s.strip().strip('"').strip("'")
                for s in raw_sources.split(",")
                if s.strip()
            ]
            allows_public = any(s in ("0.0.0.0/0", "::/0") for s in sources)

            # Check allowed ports
            allow_blocks = re.findall(r'allow\s*\{(.*?)\}', block, re.DOTALL)
            ftp_allowed = False
            for allow in allow_blocks:
                proto_match = re.search(r'protocol\s*=\s*"([^"]+)"', allow)
                protocol = proto_match.group(1).lower() if proto_match else ""
                if protocol not in ("tcp", "all"):
                    continue

                ports_match = re.search(r'ports\s*=\s*\[([^\]]*)\]', allow)
                if ports_match:
                    ports_raw = ports_match.group(1)
                    ports = [
                        p.strip().strip('"').strip("'")
                        for p in ports_raw.split(",")
                        if p.strip()
                    ]
                    if any(is_port_in_range(21, p) for p in ports):
                        ftp_allowed = True
                else:
                    # No ports specified means all ports are allowed
                    ftp_allowed = True

            self.assertFalse(
                allows_public and ftp_allowed,
                f"Firewall resource '{name}' allows unrestricted FTP access (port 21) from 0.0.0.0/0",
            )


if __name__ == "__main__":
    unittest.main()