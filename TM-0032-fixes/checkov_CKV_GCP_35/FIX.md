### Vulnerability Description
Checkov rule `CKV_GCP_35` flags Compute Engine VM instances that have serial port access enabled. In Google Cloud Platform, connecting to serial ports bypasses traditional IP-level network controls and firewalls. If an attacker gains IAM permissions or serial console access, interactive serial console access can be used to authenticate, reboot, or execute commands on the machine, increasing the attack surface.

### Evidence
In `terraform/gcp/instances.tf` at line 22, the metadata block for `google_compute_instance.server` explicitly enables the serial console:
```terraform
  metadata = {
    block-project-ssh-keys = false
    enable-oslogin         = false
    serial-port-enable     = true
  }
```

### Remediation
Changed `serial-port-enable` from `true` to `false` in the `metadata` block of `google_compute_instance.server`. This ensures serial console connections to the VM instance are blocked.

### Verification
Run `pytest test_instances_serial_port.py` or run `checkov -f terraform/gcp/instances.tf --check CKV_GCP_35` to verify that the check passes.