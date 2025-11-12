# Test Configurations

Place your test configuration files here.

**⚠️ NEVER commit real firewall configs to git!**

This directory is git-ignored for security.

## Usage
```bash
# Add your config
cp ~/Downloads/firewall_backup.conf test_configs/

# Run offline audit
python ../offline_auditor.py --config test_configs/firewall_backup.conf
```
