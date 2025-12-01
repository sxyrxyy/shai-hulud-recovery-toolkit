# 🛡️ Shai-Hulud 2.0 Detection, Recovery, and Remediation Script

A comprehensive Python script to identify, recover from, and remediate Shai-Hulud 2.0 supply chain attacks.

## Overview

Shai-Hulud 2.0 is a large-scale, self-replicating supply-chain malware campaign that spread through the npm ecosystem. This script provides automated detection and remediation capabilities based on the official playbook and industry best practices.

## Features

### Detection Capabilities
- ✅ Scans for known malicious files (`setup_bun.js`, `bun_environment.js`, etc.)
- ✅ Verifies file hashes against known malicious signatures
- ✅ Detects suspicious `package.json` lifecycle scripts
- ✅ Identifies compromised npm packages and versions
- ✅ Scans GitHub workflows for suspicious patterns
- ✅ Checks npm cache for malicious artifacts
- ✅ **Scans Git repositories for suspicious activity**
- ✅ **Detects missing .git directories (destructive cleanup indicator)**
- ✅ **Identifies suspicious git commits and remotes**
- ✅ **Checks git hooks and config for malicious content**
- ✅ Generates comprehensive JSON reports

### Remediation Capabilities
- 🛠️ Removes malicious files automatically
- 🛠️ Cleans npm environment (node_modules, cache)
- 🛠️ Fixes suspicious package.json scripts
- 🛠️ Removes compromised packages
- 🛠️ **Remediates Git issues (removes suspicious remotes, hooks)**
- 🛠️ **Provides guidance for suspicious git commits**
- 🛠️ Provides credential rotation checklist
- 🛠️ GitHub audit guidance
- 🛠️ Long-term hardening measures

## Requirements

- Python 3.6 or higher
- npm (for remediation features)
- git (for Git repository scanning)
- Access to the project directory you want to scan

## Installation

No installation required! The script is self-contained. Just ensure you have Python 3 installed.

```bash
# Make script executable (optional)
chmod +x shai_hulud_recovery.py
```

## Usage

### Basic Detection Scan

```bash
# Scan current directory
python shai_hulud_recovery.py --scan .

# Scan specific directory
python shai_hulud_recovery.py --scan /path/to/project
```

### Detection + Remediation

```bash
# Interactive remediation (recommended)
python shai_hulud_recovery.py --scan . --remediate

# Non-interactive mode (auto-confirm all actions)
python shai_hulud_recovery.py --scan . --remediate --non-interactive
```

### Detection Only (No Remediation)

```bash
python shai_hulud_recovery.py --scan . --detect-only
```

### Quiet Mode

```bash
python shai_hulud_recovery.py --scan . --quiet
```

## Command Line Options

```
--scan, -s PATH          Path to scan (default: current directory)
--remediate, -r          Run remediation after detection
--detect-only, -d        Only run detection, skip remediation
--non-interactive, -n    Non-interactive mode (auto-confirm actions)
--quiet, -q              Quiet mode (less output)
--help, -h               Show help message
```

## What the Script Detects

### Malicious Files
- `setup_bun.js`
- `bun_environment.js`
- `environment.json`
- `cloud.json`
- `contents.json`
- `truffleSecrets.json`
- `data.json`

### Known Malicious Hashes
- `bun_environment.js`: SHA1 `d60ec97eea19fffb4809bc35b91033b52490ca11`
- `setup_bun.js`: SHA1 `d1829b4708126dcc7bea7437c04d1f10eacd4a16`

### Suspicious Patterns
- `preinstall`/`postinstall` scripts referencing `setup_bun` or `bun_environment`
- Obfuscated scripts (base64, eval, etc.)
- Suspicious GitHub workflow files
- Compromised npm packages

### Git Repository Checks
- **Suspicious git remotes** (webhook.site, shai-hulud references)
- **Suspicious git commits** (commits with malicious keywords)
- **Malicious files tracked in git** (IOC files committed to repository)
- **Suspicious git hooks** (hooks containing malicious code)
- **Suspicious git config** (config values with malicious patterns)
- **Missing .git directories** (indicates destructive cleanup by malware)

## Output

The script generates:
1. **Console output** with color-coded findings
2. **JSON report** file: `shai_hulud_report_YYYYMMDD_HHMMSS.json`

### Report Structure

```json
{
  "scan_timestamp": "2025-11-27T12:00:00",
  "scan_path": "/path/to/project",
  "summary": {
    "total_findings": 5,
    "critical": 2,
    "high": 3,
    "malicious_files": 2,
    "compromised_packages": 1,
    "suspicious_workflows": 1,
    "git_issues": 1,
    "suspicious_git_commits": 0,
    "suspicious_git_remotes": 1,
    "missing_git_dirs": 0
  },
  "findings": {
    "malicious_files": [...],
    "suspicious_package_json": [...],
    "compromised_packages": [...],
    "suspicious_workflows": [...],
    "hash_matches": [...],
    "git_issues": [...],
    "suspicious_git_commits": [...],
    "suspicious_git_remotes": [...],
    "missing_git_dirs": [...]
  }
}
```

## Emergency Response Checklist

If the script detects findings, follow these steps:

1. ✅ **Scan for IOCs** - Run full detection scan
2. ✅ **Stop all CI/CD** - Disable GitHub Actions and automation
3. ✅ **Revoke ALL credentials** - GitHub PATs, npm tokens, cloud keys
4. ✅ **Disable publishing** - Disable GitHub Actions & npm publishing
5. ✅ **Purge caches** - Remove node_modules and npm cache
6. ✅ **Remove IOC files** - Delete all malicious files
7. ✅ **Rebuild machines** - Reinstall OS on compromised machines
8. ✅ **Restore from backups** - Use verified pre-infection backups
9. ✅ **Regenerate dependencies** - Safely reinstall with verified packages
10. ✅ **Re-enable securely** - Re-enable CI/CD with new credentials
11. ✅ **Implement hardening** - Apply long-term security measures

## Credential Rotation Checklist

Immediately revoke and rotate:
1. GitHub Personal Access Tokens (PATs)
2. GitHub SSH keys
3. npm tokens
4. AWS access keys (AKIA)
5. GCP service account keys
6. Azure service principal credentials
7. Discord webhooks
8. API keys in .env files
9. Database credentials
10. CI/CD runner tokens
11. Docker registry credentials
12. Cloud provider API keys

⚠️ **Treat EVERY credential on the compromised machine as compromised**

## GitHub Audit Checklist

1. Check for new public repositories with suspicious names
2. Review repository creation history
3. Check for unauthorized commits from unusual IPs
4. Review force pushes you didn't initiate
5. Audit workflow files for suspicious changes
6. Check for unauthorized self-hosted runner registrations
7. Review GitHub Actions logs for suspicious activity
8. Check for unauthorized package publishing events
9. Review organization member access
10. Check for new SSH keys or deploy keys

### GitHub CLI Commands

```bash
# List all repositories
gh repo list --limit 1000

# Find suspicious repositories
gh api /user/repos --jq '.[] | select(.name | test("shai|hulud"; "i"))'

# Check runners
gh api /orgs/{org}/actions/runners
```

## Git Repository Remediation

If the script detects git-related issues, it can help remediate:

### Suspicious Git Remotes
- Automatically removes remotes containing `webhook.site`, `shai`, or `hulud` patterns
- Prompts for confirmation before removal

### Suspicious Git Commits
- Lists commits with suspicious messages
- Provides guidance for manual review
- Recommends reverting or removing malicious commits

### Malicious Files in Git
- Removes malicious files from git tracking
- Keeps files on disk (use `git rm --cached`)
- Provides commit instructions

### Suspicious Git Hooks
- Removes malicious git hooks
- Checks all hook files for suspicious patterns

### Missing .git Directories
- Detects when `.git` directories are missing (destructive cleanup indicator)
- Provides recovery guidance
- Recommends backup restoration

### Manual Git Remediation Commands

```bash
# Review recent commits
git log --oneline -20 --all

# Check commit details
git show <commit-hash>

# Remove suspicious remote
git remote remove <remote-name>

# Remove file from git (keep on disk)
git rm --cached <file>

# Review git config
git config --list

# Remove suspicious config entry
git config --unset <key>

# Check git hooks
ls -la .git/hooks/

# Review reflog for force pushes
git reflog --all -20
```

## Long-Term Hardening Measures

1. **Disable npm lifecycle scripts**
   ```bash
   npm config set ignore-scripts true
   ```

2. **Pin exact package versions**
   - Use exact versions in package.json
   - Avoid `^` and `~` operators
   - Commit lockfiles

3. **Enable GitHub security features**
   - Mandatory 2FA
   - Branch protection
   - Workflow changes requiring PR review
   - Secret scanning
   - Dependency review
   - CodeQL

4. **Use short-lived tokens**
   - Prefer GitHub OIDC for CI authentication
   - No long-lived PATs
   - Rotate every 30-90 days

## Exit Codes

- `0` - No findings detected
- `1` - Non-critical findings detected
- `2` - Critical findings detected

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Shai-Hulud 2.0 Detection

on:
  push:
    paths:
      - '**/package.json'
      - '**/package-lock.json'
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight UTC

jobs:
  detect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Run Shai-Hulud Detection
        run: |
          python shai_hulud_recovery.py --scan . --detect-only --quiet
```
