# Run via: pytest test_mssql_azuread_auth.py (or REPO_ROOT=. python3 -m unittest test_mssql_azuread_auth.py)
import os
import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


def extract_resources(content: str, resource_type: str) -> dict:
    resources = {}
    pattern = re.compile(rf'resource\s+"{re.escape(resource_type)}"\s+"([^"]+)"\s*\{{')
    for match in pattern.finditer(content):
        name = match.group(1)
        start = match.end()
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        resources[name] = content[start : i - 1]
    return resources


class TestMSSQLAzureADAuth(unittest.TestCase):
    def test_all_mssql_servers_have_azuread_administrator(self):
        target_file = REPO_ROOT / "terraform/azure/mssql.tf"
        self.assertTrue(target_file.is_file(), f"{target_file} does not exist")
        content = target_file.read_text(encoding="utf-8")

        mssql_servers = extract_resources(content, "azurerm_mssql_server")
        self.assertGreater(len(mssql_servers), 0, "Expected at least one azurerm_mssql_server")

        for name, block in mssql_servers.items():
            with self.subTest(server=name):
                self.assertRegex(
                    block,
                    r"azuread_administrator\s*\{",
                    f"Resource azurerm_mssql_server.{name} is missing azuread_administrator block",
                )


if __name__ == "__main__":
    unittest.main()