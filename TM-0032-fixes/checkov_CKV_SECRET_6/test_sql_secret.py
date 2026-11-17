# pytest test_sql_secret.py
import hashlib
import os
import pathlib
import unittest

REPO_ROOT = pathlib.Path(os.environ.get("REPO_ROOT", "."))


class TestSqlSecret(unittest.TestCase):
    def test_no_hardcoded_admin_password(self):
        sql_tf_path = REPO_ROOT / "terraform/azure/sql.tf"
        self.assertTrue(sql_tf_path.exists(), f"File not found: {sql_tf_path}")
        content = sql_tf_path.read_text(encoding="utf-8")

        # SHA-1 hash of the secret reported by Checkov CKV_SECRET_6
        flagged_secret_hash = "a57ae0fe47084bc8a05f69f3f8083896f8b437b0"

        # Assert the literal password is not present
        self.assertNotIn(
            "Aa12345678",
            content,
            "Hardcoded database administrator password 'Aa12345678' found in terraform/azure/sql.tf",
        )

        # Assert that no administrator_login_password line matches the flagged secret hash
        for line in content.splitlines():
            if "administrator_login_password" in line and "=" in line:
                raw_val = line.split("=", 1)[1].strip().strip('"')
                val_hash = hashlib.sha1(raw_val.encode("utf-8")).hexdigest()
                self.assertNotEqual(
                    val_hash,
                    flagged_secret_hash,
                    f"Line contains secret matching flagged hash {flagged_secret_hash}: {line.strip()}",
                )


if __name__ == "__main__":
    unittest.main()