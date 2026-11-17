### Vulnerability Details
Alibaba Cloud ActionTrail records actions taken by users, roles, and services across your cloud environment. In `terraform/alicloud/trail.tf`, the `alicloud_actiontrail_trail.fail` resource was configured with `event_rw = "Read"` (line 7). 

Because write events were excluded from logging, any state-altering operations—such as creating, modifying, or deleting infrastructure, modifying permissions, or tampering with configurations—would not be logged to the ActionTrail destination. This violates NIST AU-2, AU-3, and AU-12 auditing controls and fails Checkov check `CKV_ALI_5`.

### Fix
Updated `event_rw = "Read"` to `event_rw = "All"` in `terraform/alicloud/trail.tf` so that both read and write operations are captured.

### Verification
- Run `pytest test_actiontrail_logging.py` (or `python -m unittest test_actiontrail_logging.py`). It will fail against the original `"Read"` setting and pass with `"All"`.
- Run Checkov against the file: `checkov -f terraform/alicloud/trail.tf --check CKV_ALI_5`.