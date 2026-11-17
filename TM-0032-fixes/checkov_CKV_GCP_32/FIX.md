### Vulnerability Details
In Google Cloud Platform (GCP), project-wide SSH keys configured at the project metadata level grant SSH access across all compute instances in the project by default. When `block-project-ssh-keys` is disabled or set to `false`, any user or service account with project-level metadata modification privileges can inject SSH keys and gain root or administrative access to all VMs across the project, violating the principle of least privilege and expanding the attack surface.

### Evidence
In `terraform/gcp/instances.tf`, lines 19-23 explicitly disabled this protection on `google_compute_instance.server`:
```hcl
  metadata = {
    block-project-ssh-keys = false
    enable-oslogin         = false
    serial-port-enable     = true
  }
```

### Remediation
The `block-project-ssh-keys` metadata property was changed from `false` to `true`. This ensures the instance does not inherit project-wide SSH keys and only explicitly defined instance-level keys (or IAM/OS Login policies) are permitted for SSH access.

### Verification
Run `python -m unittest test_instances_ssh_keys.py` (or `pytest test_instances_ssh_keys.py`) from the repository root to verify that `block-project-ssh-keys` is set to `true` in `google_compute_instance.server`.