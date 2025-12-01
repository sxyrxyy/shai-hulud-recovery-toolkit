#!/usr/bin/env python3

import os
import sys
import json
import hashlib
import subprocess
import shutil
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime
import argparse

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Known IOCs from the playbook
MALICIOUS_FILES = [
    'setup_bun.js',
    'bun_environment.js',
    'environment.json',
    'cloud.json',
    'contents.json',
    'truffleSecrets.json',
    'data.json'
]

# Known malicious file hashes
MALICIOUS_HASHES = {
    'bun_environment.js': {
        'sha1': 'd60ec97eea19fffb4809bc35b91033b52490ca11',
        'sha256': '3d7570d14d34b0ba137d502f042b27b0f37a59fa'
    },
    'setup_bun.js': {
        'sha1': 'd1829b4708126dcc7bea7437c04d1f10eacd4a16'
    }
}

# Suspicious GitHub repo names
SUSPICIOUS_REPO_NAMES = [
    'shai-hulud',
    'sha1-hulud',
    'shai-hulud migration',
    'sha1-hulud: the second coming',
    'sha1-hulud: the continued coming'
]

# Suspicious workflow patterns
SUSPICIOUS_WORKFLOW_PATTERNS = [
    r'discussion\.yaml',
    r'setup_bun',
    r'bun_environment',
    r'webhook\.site',
    r'eval\s*\(',
    r'base64',
    r'atob\s*\('
]

# Known compromised packages (sample from Wiz blog - update with latest list)
COMPROMISED_PACKAGES = [
    '@postman/tunnel-agent',
    'posthog-node',
    '@asyncapi/specs',
    'posthog-js',
    'get-them-args',
    'shell-exec',
    'kill-port',
    'zapier-platform-cli',
    'zapier-platform-core'
]

# Compromised package versions (sample - should be updated from latest IOCs)
COMPROMISED_VERSIONS = {
    '@postman/tunnel-agent': ['1.0.1', '1.0.2'],
    'posthog-node': ['1.0.1'],
    'zapier-platform-cli': ['18.0.2', '18.0.3', '18.0.4']
}


class ShaiHuludDetector:
    """Main detection and remediation class"""
    
    def __init__(self, scan_path: str = '.', verbose: bool = True):
        self.scan_path = Path(scan_path).resolve()
        self.verbose = verbose
        self.findings = {
            'malicious_files': [],
            'suspicious_package_json': [],
            'compromised_packages': [],
            'suspicious_workflows': [],
            'hash_matches': [],
            'suspicious_scripts': [],
            'git_issues': [],
            'suspicious_git_commits': [],
            'suspicious_git_remotes': [],
            'missing_git_dirs': []
        }
        self.report_file = f'shai_hulud_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
    def print_header(self, text: str):
        """Print formatted header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")
    
    def print_error(self, text: str):
        """Print error message"""
        print(f"{Colors.RED}❌ {text}{Colors.END}")
    
    def print_success(self, text: str):
        """Print success message"""
        print(f"{Colors.GREEN}✅ {text}{Colors.END}")
    
    def print_info(self, text: str):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")
    
    def calculate_hash(self, file_path: Path, algorithm: str = 'sha1') -> str:
        """Calculate file hash"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            if self.verbose:
                self.print_warning(f"Could not calculate hash for {file_path}: {e}")
            return ''
    
    def scan_malicious_files(self) -> List[Dict]:
        """Scan for known malicious files"""
        self.print_header("Scanning for Malicious Files")
        findings = []
        
        for malicious_file in MALICIOUS_FILES:
            for file_path in self.scan_path.rglob(malicious_file):
                if file_path.is_file():
                    finding = {
                        'file': str(file_path),
                        'type': 'malicious_file',
                        'severity': 'critical'
                    }
                    
                    # Check hash if it's a known malicious file
                    filename = file_path.name
                    if filename in MALICIOUS_HASHES:
                        file_hash_sha1 = self.calculate_hash(file_path, 'sha1')
                        file_hash_sha256 = self.calculate_hash(file_path, 'sha256')
                        
                        if filename in MALICIOUS_HASHES:
                            if 'sha1' in MALICIOUS_HASHES[filename]:
                                if file_hash_sha1 == MALICIOUS_HASHES[filename]['sha1']:
                                    finding['hash_match'] = 'sha1'
                                    finding['severity'] = 'critical'
                                    self.findings['hash_matches'].append(finding)
                            
                            if 'sha256' in MALICIOUS_HASHES[filename]:
                                if file_hash_sha256 == MALICIOUS_HASHES[filename]['sha256']:
                                    finding['hash_match'] = 'sha256'
                                    finding['severity'] = 'critical'
                                    self.findings['hash_matches'].append(finding)
                    
                    findings.append(finding)
                    self.findings['malicious_files'].append(finding)
                    self.print_error(f"Found malicious file: {file_path}")
        
        if not findings:
            self.print_success("No malicious files found")
        else:
            self.print_warning(f"Found {len(findings)} malicious file(s)")
        
        return findings
    
    def scan_package_json(self) -> List[Dict]:
        """Scan package.json files for suspicious scripts"""
        self.print_header("Scanning package.json Files")
        findings = []
        
        for package_json in self.scan_path.rglob('package.json'):
            if package_json.is_file():
                try:
                    with open(package_json, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    scripts = data.get('scripts', {})
                    suspicious_scripts = []
                    
                    # Check for suspicious preinstall/postinstall scripts
                    for script_name, script_content in scripts.items():
                        if script_name in ['preinstall', 'postinstall', 'install']:
                            if any(pattern in script_content.lower() for pattern in ['setup_bun', 'bun_environment', 'eval', 'base64']):
                                suspicious_scripts.append({
                                    'script': script_name,
                                    'content': script_content
                                })
                    
                    if suspicious_scripts:
                        finding = {
                            'file': str(package_json),
                            'type': 'suspicious_package_json',
                            'severity': 'high',
                            'suspicious_scripts': suspicious_scripts
                        }
                        findings.append(finding)
                        self.findings['suspicious_package_json'].append(finding)
                        self.print_error(f"Suspicious scripts in {package_json}")
                        for script in suspicious_scripts:
                            self.print_warning(f"  - {script['script']}: {script['content']}")
                
                except json.JSONDecodeError:
                    if self.verbose:
                        self.print_warning(f"Could not parse {package_json}")
                except Exception as e:
                    if self.verbose:
                        self.print_warning(f"Error scanning {package_json}: {e}")
        
        if not findings:
            self.print_success("No suspicious package.json files found")
        else:
            self.print_warning(f"Found {len(findings)} suspicious package.json file(s)")
        
        return findings
    
    def scan_compromised_packages(self) -> List[Dict]:
        """Scan for compromised npm packages"""
        self.print_header("Scanning for Compromised Packages")
        findings = []
        
        # Check package.json and package-lock.json
        for lock_file in [self.scan_path / 'package-lock.json', 
                         self.scan_path / 'yarn.lock',
                         self.scan_path / 'pnpm-lock.yaml']:
            if not lock_file.exists():
                continue
            
            try:
                if lock_file.name == 'package-lock.json':
                    with open(lock_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        dependencies = data.get('dependencies', {})
                        
                        for pkg_name, pkg_info in dependencies.items():
                            version = pkg_info.get('version', '')
                            
                            # Check if package is in compromised list
                            if pkg_name in COMPROMISED_PACKAGES:
                                # Check if version is compromised
                                if pkg_name in COMPROMISED_VERSIONS:
                                    if version in COMPROMISED_VERSIONS[pkg_name]:
                                        finding = {
                                            'package': pkg_name,
                                            'version': version,
                                            'type': 'compromised_package',
                                            'severity': 'critical',
                                            'source': str(lock_file)
                                        }
                                        findings.append(finding)
                                        self.findings['compromised_packages'].append(finding)
                                        self.print_error(f"Compromised package found: {pkg_name}@{version}")
                                else:
                                    # Package is compromised but version unknown
                                    finding = {
                                        'package': pkg_name,
                                        'version': version,
                                        'type': 'compromised_package',
                                        'severity': 'high',
                                        'source': str(lock_file),
                                        'note': 'Package is compromised, verify version'
                                    }
                                    findings.append(finding)
                                    self.findings['compromised_packages'].append(finding)
                                    self.print_warning(f"Potentially compromised package: {pkg_name}@{version}")
            
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error scanning {lock_file}: {e}")
        
        # Also check package.json directly
        package_json = self.scan_path / 'package.json'
        if package_json.exists():
            try:
                with open(package_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                all_deps = {}
                all_deps.update(data.get('dependencies', {}))
                all_deps.update(data.get('devDependencies', {}))
                
                for pkg_name, version_spec in all_deps.items():
                    if pkg_name in COMPROMISED_PACKAGES:
                        finding = {
                            'package': pkg_name,
                            'version_spec': version_spec,
                            'type': 'compromised_package',
                            'severity': 'high',
                            'source': str(package_json),
                            'note': 'Package is compromised, check installed version'
                        }
                        findings.append(finding)
                        self.findings['compromised_packages'].append(finding)
                        self.print_warning(f"Potentially compromised package in package.json: {pkg_name}@{version_spec}")
            
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error scanning {package_json}: {e}")
        
        if not findings:
            self.print_success("No compromised packages found in dependency files")
        else:
            self.print_warning(f"Found {len(findings)} compromised package(s)")
        
        return findings
    
    def scan_workflows(self) -> List[Dict]:
        """Scan GitHub workflows for suspicious patterns"""
        self.print_header("Scanning GitHub Workflows")
        findings = []
        
        workflows_dir = self.scan_path / '.github' / 'workflows'
        if not workflows_dir.exists():
            if self.verbose:
                self.print_info("No .github/workflows directory found")
            return findings
        
        for workflow_file in workflows_dir.rglob('*.yml'):
            if not workflow_file.is_file():
                continue
            
            # Check for suspicious file names
            if any(pattern in workflow_file.name.lower() for pattern in ['discussion', 'setup_bun', 'bun']):
                finding = {
                    'file': str(workflow_file),
                    'type': 'suspicious_workflow',
                    'severity': 'high',
                    'reason': 'Suspicious filename'
                }
                findings.append(finding)
                self.findings['suspicious_workflows'].append(finding)
                self.print_error(f"Suspicious workflow filename: {workflow_file}")
                continue
            
            # Check file content
            try:
                with open(workflow_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in SUSPICIOUS_WORKFLOW_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        finding = {
                            'file': str(workflow_file),
                            'type': 'suspicious_workflow',
                            'severity': 'high',
                            'reason': f'Contains suspicious pattern: {pattern}'
                        }
                        findings.append(finding)
                        self.findings['suspicious_workflows'].append(finding)
                        self.print_error(f"Suspicious pattern in workflow: {workflow_file} - {pattern}")
                        break
            
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error scanning {workflow_file}: {e}")
        
        if not findings:
            self.print_success("No suspicious workflows found")
        else:
            self.print_warning(f"Found {len(findings)} suspicious workflow(s)")
        
        return findings
    
    def scan_npm_cache(self) -> List[Dict]:
        """Scan npm cache for malicious files"""
        self.print_header("Scanning npm Cache")
        findings = []
        
        npm_cache_paths = [
            Path.home() / '.npm',
            Path('/tmp/.npm'),
        ]
        
        for cache_path in npm_cache_paths:
            if not cache_path.exists():
                continue
            
            for malicious_file in MALICIOUS_FILES:
                for file_path in cache_path.rglob(malicious_file):
                    if file_path.is_file():
                        finding = {
                            'file': str(file_path),
                            'type': 'malicious_file_in_cache',
                            'severity': 'high',
                            'cache_location': str(cache_path)
                        }
                        findings.append(finding)
                        self.findings['malicious_files'].append(finding)
                        self.print_error(f"Found malicious file in cache: {file_path}")
        
        if not findings:
            self.print_success("No malicious files found in npm cache")
        else:
            self.print_warning(f"Found {len(findings)} malicious file(s) in cache")
        
        return findings
    
    def scan_git_projects(self) -> List[Dict]:
        """Scan Git repositories for suspicious activity"""
        self.print_header("Scanning Git Projects")
        findings = []
        
        # Find all .git directories
        git_dirs = list(self.scan_path.rglob('.git'))
        
        if not git_dirs:
            if self.verbose:
                self.print_info("No .git directories found")
            # Check if this should be a git repo but .git is missing (destructive behavior)
            if (self.scan_path / 'package.json').exists() or (self.scan_path / 'README.md').exists():
                # Could indicate .git was deleted by malware
                finding = {
                    'path': str(self.scan_path),
                    'type': 'missing_git_dir',
                    'severity': 'high',
                    'note': 'Project appears to be a codebase but .git directory is missing (possible destructive cleanup)'
                }
                findings.append(finding)
                self.findings['missing_git_dirs'].append(finding)
                self.print_warning(f"Potential missing .git directory in {self.scan_path}")
            return findings
        
        for git_dir in git_dirs:
            if not git_dir.is_dir():
                continue
            
            repo_path = git_dir.parent
            
            # Check if git is available
            try:
                result = subprocess.run(['git', '--version'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
                if result.returncode != 0:
                    if self.verbose:
                        self.print_warning(f"Git not available, skipping {repo_path}")
                    continue
            except FileNotFoundError:
                if self.verbose:
                    self.print_warning("Git command not found, skipping git scans")
                return findings
            
            self.print_info(f"Scanning Git repository: {repo_path}")
            
            # Check for suspicious remotes
            try:
                result = subprocess.run(['git', 'remote', '-v'], 
                                      cwd=repo_path,
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    remotes = result.stdout
                    # Check for suspicious remote URLs
                    suspicious_remotes = []
                    for line in remotes.split('\n'):
                        if not line.strip():
                            continue
                        # Check for webhook sites or suspicious patterns
                        if any(pattern in line.lower() for pattern in ['webhook.site', 'shai', 'hulud']):
                            suspicious_remotes.append(line.strip())
                    
                    if suspicious_remotes:
                        finding = {
                            'repo': str(repo_path),
                            'type': 'suspicious_git_remote',
                            'severity': 'high',
                            'remotes': suspicious_remotes
                        }
                        findings.append(finding)
                        self.findings['suspicious_git_remotes'].append(finding)
                        self.print_error(f"Suspicious git remotes in {repo_path}")
                        for remote in suspicious_remotes:
                            self.print_warning(f"  - {remote}")
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error checking remotes in {repo_path}: {e}")
            
            # Check recent commits for suspicious activity
            try:
                # Get last 20 commits
                result = subprocess.run(['git', 'log', '--oneline', '-20', '--all'], 
                                      cwd=repo_path,
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    commits = result.stdout
                    suspicious_commits = []
                    
                    for line in commits.split('\n'):
                        if not line.strip():
                            continue
                        commit_hash = line.split()[0] if line.split() else ''
                        commit_msg = ' '.join(line.split()[1:]) if len(line.split()) > 1 else ''
                        
                        # Check for suspicious commit messages
                        if any(pattern in commit_msg.lower() for pattern in ['shai', 'hulud', 'setup_bun', 'bun_environment']):
                            suspicious_commits.append({
                                'hash': commit_hash,
                                'message': commit_msg
                            })
                    
                    if suspicious_commits:
                        finding = {
                            'repo': str(repo_path),
                            'type': 'suspicious_git_commits',
                            'severity': 'high',
                            'commits': suspicious_commits
                        }
                        findings.append(finding)
                        self.findings['suspicious_git_commits'].append(finding)
                        self.print_error(f"Suspicious commits found in {repo_path}")
                        for commit in suspicious_commits:
                            self.print_warning(f"  - {commit['hash']}: {commit['message']}")
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error checking commits in {repo_path}: {e}")
            
            # Check for suspicious files in git history
            try:
                result = subprocess.run(['git', 'ls-files'], 
                                      cwd=repo_path,
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    tracked_files = result.stdout.split('\n')
                    for malicious_file in MALICIOUS_FILES:
                        if malicious_file in tracked_files:
                            finding = {
                                'repo': str(repo_path),
                                'file': malicious_file,
                                'type': 'malicious_file_in_git',
                                'severity': 'critical',
                                'note': 'Malicious file is tracked in git repository'
                            }
                            findings.append(finding)
                            self.findings['git_issues'].append(finding)
                            self.print_error(f"Malicious file tracked in git: {repo_path}/{malicious_file}")
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error checking tracked files in {repo_path}: {e}")
            
            # Check git hooks for suspicious content
            hooks_dir = git_dir / 'hooks'
            if hooks_dir.exists():
                for hook_file in hooks_dir.iterdir():
                    if hook_file.is_file() and hook_file.suffix != '.sample':
                        try:
                            with open(hook_file, 'r', encoding='utf-8', errors='ignore') as f:
                                hook_content = f.read()
                            
                            # Check for suspicious patterns in hooks
                            if any(pattern in hook_content.lower() for pattern in ['setup_bun', 'bun_environment', 'webhook.site', 'eval(', 'base64']):
                                finding = {
                                    'repo': str(repo_path),
                                    'hook': str(hook_file.name),
                                    'type': 'suspicious_git_hook',
                                    'severity': 'high',
                                    'file': str(hook_file)
                                }
                                findings.append(finding)
                                self.findings['git_issues'].append(finding)
                                self.print_error(f"Suspicious git hook: {repo_path}/.git/hooks/{hook_file.name}")
                        except Exception as e:
                            if self.verbose:
                                self.print_warning(f"Error reading hook {hook_file}: {e}")
            
            # Check git config for suspicious settings
            try:
                result = subprocess.run(['git', 'config', '--list'], 
                                      cwd=repo_path,
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    config = result.stdout
                    # Check for suspicious config values
                    if any(pattern in config.lower() for pattern in ['webhook.site', 'shai', 'hulud']):
                        finding = {
                            'repo': str(repo_path),
                            'type': 'suspicious_git_config',
                            'severity': 'medium',
                            'note': 'Suspicious patterns found in git config'
                        }
                        findings.append(finding)
                        self.findings['git_issues'].append(finding)
                        self.print_warning(f"Suspicious git config in {repo_path}")
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error checking git config in {repo_path}: {e}")
            
            # Check for force push indicators (check reflog)
            try:
                result = subprocess.run(['git', 'reflog', '--all', '-20'], 
                                      cwd=repo_path,
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                if result.returncode == 0:
                    reflog = result.stdout
                    # Look for force push patterns
                    if 'force' in reflog.lower() or 'reset' in reflog.lower():
                        # This is just informational, not necessarily malicious
                        if self.verbose:
                            self.print_info(f"Recent force/reset operations detected in {repo_path} (review manually)")
            except Exception as e:
                if self.verbose:
                    self.print_warning(f"Error checking reflog in {repo_path}: {e}")
        
        if not findings:
            self.print_success("No suspicious git activity found")
        else:
            self.print_warning(f"Found {len(findings)} git-related issue(s)")
        
        return findings
    
    def generate_report(self):
        """Generate comprehensive report"""
        self.print_header("Generating Report")
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'scan_path': str(self.scan_path),
            'summary': {
                'total_findings': sum(len(v) for v in self.findings.values()),
                'critical': len([f for findings in self.findings.values() for f in findings if f.get('severity') == 'critical']),
                'high': len([f for findings in self.findings.values() for f in findings if f.get('severity') == 'high']),
                'malicious_files': len(self.findings['malicious_files']),
                'suspicious_package_json': len(self.findings['suspicious_package_json']),
                'compromised_packages': len(self.findings['compromised_packages']),
                'suspicious_workflows': len(self.findings['suspicious_workflows']),
                'hash_matches': len(self.findings['hash_matches']),
                'git_issues': len(self.findings['git_issues']),
                'suspicious_git_commits': len(self.findings['suspicious_git_commits']),
                'suspicious_git_remotes': len(self.findings['suspicious_git_remotes']),
                'missing_git_dirs': len(self.findings['missing_git_dirs'])
            },
            'findings': self.findings
        }
        
        with open(self.report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.print_success(f"Report saved to: {self.report_file}")
        
        # Print summary
        print(f"\n{Colors.BOLD}Scan Summary:{Colors.END}")
        print(f"  Total Findings: {report['summary']['total_findings']}")
        print(f"  Critical: {Colors.RED}{report['summary']['critical']}{Colors.END}")
        print(f"  High: {Colors.YELLOW}{report['summary']['high']}{Colors.END}")
        print(f"  Malicious Files: {report['summary']['malicious_files']}")
        print(f"  Compromised Packages: {report['summary']['compromised_packages']}")
        print(f"  Suspicious Workflows: {report['summary']['suspicious_workflows']}")
        print(f"  Git Issues: {report['summary']['git_issues']}")
        print(f"  Suspicious Git Commits: {report['summary']['suspicious_git_commits']}")
        print(f"  Suspicious Git Remotes: {report['summary']['suspicious_git_remotes']}")
        if report['summary']['missing_git_dirs'] > 0:
            print(f"  Missing .git Directories: {Colors.RED}{report['summary']['missing_git_dirs']}{Colors.END}")
        
        return report
    
    def run_full_scan(self):
        """Run complete scan"""
        self.print_header("🛡️ Shai-Hulud 2.0 Detection Scan")
        self.print_info(f"Scanning path: {self.scan_path}")
        
        self.scan_malicious_files()
        self.scan_package_json()
        self.scan_compromised_packages()
        self.scan_workflows()
        self.scan_npm_cache()
        self.scan_git_projects()
        
        return self.generate_report()


class ShaiHuludRemediator:
    """Remediation and recovery class"""
    
    def __init__(self, detector: ShaiHuludDetector, interactive: bool = True):
        self.detector = detector
        self.interactive = interactive
    
    def print_header(self, text: str):
        """Print formatted header"""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{text}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*70}{Colors.END}\n")
    
    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")
    
    def print_error(self, text: str):
        """Print error message"""
        print(f"{Colors.RED}❌ {text}{Colors.END}")
    
    def print_success(self, text: str):
        """Print success message"""
        print(f"{Colors.GREEN}✅ {text}{Colors.END}")
    
    def print_info(self, text: str):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")
    
    def confirm_action(self, message: str) -> bool:
        """Get user confirmation"""
        if not self.interactive:
            return True
        response = input(f"{message} (yes/no): ").lower().strip()
        return response in ['yes', 'y']
    
    def remove_malicious_files(self):
        """Remove detected malicious files"""
        self.print_header("Removing Malicious Files")
        
        malicious_files = self.detector.findings['malicious_files']
        if not malicious_files:
            self.print_success("No malicious files to remove")
            return
        
        files_to_remove = []
        for finding in malicious_files:
            file_path = Path(finding['file'])
            if file_path.exists():
                files_to_remove.append(file_path)
                self.print_warning(f"Will remove: {file_path}")
        
        if not files_to_remove:
            self.print_info("No malicious files found on disk")
            return
        
        if self.confirm_action(f"Remove {len(files_to_remove)} malicious file(s)?"):
            for file_path in files_to_remove:
                try:
                    file_path.unlink()
                    self.print_success(f"Removed: {file_path}")
                except Exception as e:
                    self.print_error(f"Failed to remove {file_path}: {e}")
        else:
            self.print_info("Skipped file removal")
    
    def clean_npm_environment(self):
        """Clean npm environment"""
        self.print_header("Cleaning npm Environment")
        
        if self.confirm_action("Remove node_modules and clean npm cache?"):
            scan_path = self.detector.scan_path
            
            # Remove node_modules
            node_modules = scan_path / 'node_modules'
            if node_modules.exists():
                try:
                    shutil.rmtree(node_modules)
                    self.print_success("Removed node_modules")
                except Exception as e:
                    self.print_error(f"Failed to remove node_modules: {e}")
            
            # Clean npm cache
            try:
                result = subprocess.run(['npm', 'cache', 'clean', '--force'], 
                                       capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    self.print_success("Cleaned npm cache")
                else:
                    self.print_warning(f"npm cache clean returned: {result.stderr}")
            except FileNotFoundError:
                self.print_warning("npm not found in PATH")
            except Exception as e:
                self.print_error(f"Error cleaning npm cache: {e}")
            
            # Clean pnpm store if exists
            try:
                result = subprocess.run(['pnpm', 'store', 'prune'], 
                                       capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    self.print_success("Cleaned pnpm store")
            except FileNotFoundError:
                pass
            except Exception as e:
                self.print_warning(f"Error cleaning pnpm store: {e}")
            
            # Remove global npm cache malicious files
            npm_cache = Path.home() / '.npm'
            if npm_cache.exists():
                for malicious_file in MALICIOUS_FILES:
                    for file_path in npm_cache.rglob(malicious_file):
                        try:
                            file_path.unlink()
                            self.print_success(f"Removed from cache: {file_path}")
                        except Exception as e:
                            self.print_warning(f"Could not remove {file_path}: {e}")
        else:
            self.print_info("Skipped npm environment cleanup")
    
    def fix_package_json(self):
        """Fix suspicious package.json files"""
        self.print_header("Fixing package.json Files")
        
        suspicious = self.detector.findings['suspicious_package_json']
        if not suspicious:
            self.print_success("No suspicious package.json files to fix")
            return
        
        for finding in suspicious:
            package_json_path = Path(finding['file'])
            if not package_json_path.exists():
                continue
            
            self.print_warning(f"Reviewing: {package_json_path}")
            
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                scripts = data.get('scripts', {})
                removed_scripts = []
                
                for script_name in ['preinstall', 'postinstall', 'install']:
                    if script_name in scripts:
                        script_content = scripts[script_name]
                        if any(pattern in script_content.lower() for pattern in ['setup_bun', 'bun_environment', 'eval', 'base64']):
                            removed_scripts.append(script_name)
                            if self.confirm_action(f"Remove suspicious '{script_name}' script from {package_json_path}?"):
                                del scripts[script_name]
                                self.print_success(f"Removed '{script_name}' script")
                
                if removed_scripts:
                    data['scripts'] = scripts
                    with open(package_json_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2)
                    self.print_success(f"Updated {package_json_path}")
            
            except Exception as e:
                self.print_error(f"Error fixing {package_json_path}: {e}")
    
    def remove_compromised_packages(self):
        """Remove compromised packages"""
        self.print_header("Removing Compromised Packages")
        
        compromised = self.detector.findings['compromised_packages']
        if not compromised:
            self.print_success("No compromised packages to remove")
            return
        
        packages_to_remove = set()
        for finding in compromised:
            pkg_name = finding['package']
            packages_to_remove.add(pkg_name)
            self.print_warning(f"Compromised package: {pkg_name}@{finding.get('version', 'unknown')}")
        
        if packages_to_remove:
            self.print_info("To remove compromised packages, run:")
            for pkg in packages_to_remove:
                print(f"  npm uninstall {pkg}")
            
            if self.confirm_action("Attempt to uninstall compromised packages now?"):
                scan_path = self.detector.scan_path
                for pkg in packages_to_remove:
                    try:
                        result = subprocess.run(['npm', 'uninstall', pkg], 
                                              cwd=scan_path,
                                              capture_output=True, 
                                              text=True, 
                                              timeout=120)
                        if result.returncode == 0:
                            self.print_success(f"Uninstalled {pkg}")
                        else:
                            self.print_warning(f"Failed to uninstall {pkg}: {result.stderr}")
                    except Exception as e:
                        self.print_error(f"Error uninstalling {pkg}: {e}")
    
    def remediate_git_issues(self):
        """Remediate Git-related issues"""
        self.print_header("Remediating Git Issues")
        
        git_issues = self.detector.findings['git_issues']
        suspicious_commits = self.detector.findings['suspicious_git_commits']
        suspicious_remotes = self.detector.findings['suspicious_git_remotes']
        
        if not git_issues and not suspicious_commits and not suspicious_remotes:
            self.print_success("No git issues to remediate")
            return
        
        # Handle suspicious remotes
        if suspicious_remotes:
            self.print_warning(f"Found {len(suspicious_remotes)} suspicious git remote(s)")
            for finding in suspicious_remotes:
                repo_path = Path(finding['repo'])
                self.print_error(f"Suspicious remotes in: {repo_path}")
                
                if self.confirm_action(f"Remove suspicious remotes from {repo_path}?"):
                    try:
                        result = subprocess.run(['git', 'remote', '-v'], 
                                              cwd=repo_path,
                                              capture_output=True, 
                                              text=True, 
                                              timeout=10)
                        if result.returncode == 0:
                            # Parse remotes and remove suspicious ones
                            for line in result.stdout.split('\n'):
                                if not line.strip():
                                    continue
                                parts = line.split()
                                if len(parts) >= 2:
                                    remote_name = parts[0]
                                    remote_url = parts[1]
                                    if any(pattern in remote_url.lower() for pattern in ['webhook.site', 'shai', 'hulud']):
                                        try:
                                            subprocess.run(['git', 'remote', 'remove', remote_name], 
                                                         cwd=repo_path,
                                                         capture_output=True, 
                                                         timeout=10)
                                            self.print_success(f"Removed suspicious remote: {remote_name}")
                                        except Exception as e:
                                            self.print_error(f"Failed to remove remote {remote_name}: {e}")
                    except Exception as e:
                        self.print_error(f"Error processing remotes: {e}")
        
        # Handle suspicious commits
        if suspicious_commits:
            self.print_warning(f"Found {len(suspicious_commits)} repository(ies) with suspicious commits")
            for finding in suspicious_commits:
                repo_path = Path(finding['repo'])
                commits = finding.get('commits', [])
                self.print_error(f"Suspicious commits in: {repo_path}")
                for commit in commits:
                    self.print_warning(f"  - {commit.get('hash', 'unknown')}: {commit.get('message', '')}")
                
                self.print_info("Manual review required for suspicious commits.")
                self.print_info("Consider:")
                self.print_info("  1. Review commit history: git log")
                self.print_info("  2. Check commit details: git show <hash>")
                self.print_info("  3. If malicious, consider reverting or removing commits")
                self.print_info("  4. Force push may be required (coordinate with team)")
        
        # Handle malicious files in git
        malicious_in_git = [f for f in git_issues if f.get('type') == 'malicious_file_in_git']
        if malicious_in_git:
            self.print_warning(f"Found {len(malicious_in_git)} malicious file(s) tracked in git")
            for finding in malicious_in_git:
                repo_path = Path(finding['repo'])
                file_path = finding.get('file', '')
                self.print_error(f"Malicious file in git: {repo_path}/{file_path}")
                
                if self.confirm_action(f"Remove {file_path} from git tracking in {repo_path}?"):
                    try:
                        # Remove from git index
                        result = subprocess.run(['git', 'rm', '--cached', file_path], 
                                              cwd=repo_path,
                                              capture_output=True, 
                                              text=True, 
                                              timeout=10)
                        if result.returncode == 0:
                            self.print_success(f"Removed {file_path} from git tracking")
                            self.print_info("Commit this change: git commit -m 'Remove malicious file'")
                        else:
                            self.print_warning(f"Failed to remove from git: {result.stderr}")
                    except Exception as e:
                        self.print_error(f"Error removing from git: {e}")
        
        # Handle suspicious git hooks
        suspicious_hooks = [f for f in git_issues if f.get('type') == 'suspicious_git_hook']
        if suspicious_hooks:
            self.print_warning(f"Found {len(suspicious_hooks)} suspicious git hook(s)")
            for finding in suspicious_hooks:
                hook_file = Path(finding.get('file', ''))
                repo_path = Path(finding['repo'])
                self.print_error(f"Suspicious hook: {hook_file}")
                
                if self.confirm_action(f"Remove suspicious hook {hook_file.name}?"):
                    try:
                        if hook_file.exists():
                            hook_file.unlink()
                            self.print_success(f"Removed hook: {hook_file}")
                        else:
                            self.print_warning(f"Hook file not found: {hook_file}")
                    except Exception as e:
                        self.print_error(f"Failed to remove hook: {e}")
        
        # Handle missing .git directories (destructive cleanup indicator)
        missing_git_dirs = self.detector.findings['missing_git_dirs']
        if missing_git_dirs:
            self.print_warning(f"Found {len(missing_git_dirs)} project(s) with missing .git directory")
            self.print_error("This may indicate destructive cleanup by malware!")
            self.print_info("Actions to take:")
            self.print_info("  1. Check if you have backups of the .git directory")
            self.print_info("  2. If available, restore from backup")
            self.print_info("  3. If not, you may need to reinitialize git: git init")
            self.print_info("  4. Re-add files and create initial commit")
            self.print_info("  5. Reconnect to remote if needed")
        
        # Handle suspicious git config
        suspicious_config = [f for f in git_issues if f.get('type') == 'suspicious_git_config']
        if suspicious_config:
            self.print_warning(f"Found {len(suspicious_config)} repository(ies) with suspicious git config")
            for finding in suspicious_config:
                repo_path = Path(finding['repo'])
                self.print_error(f"Suspicious config in: {repo_path}")
                self.print_info("Review git config manually:")
                self.print_info(f"  cd {repo_path} && git config --list")
                self.print_info("Remove any suspicious entries:")
                self.print_info("  git config --unset <key>")
    
    def credential_rotation_checklist(self):
        """Display credential rotation checklist"""
        self.print_header("Credential Rotation Checklist")
        
        credentials = [
            "GitHub Personal Access Tokens (PATs)",
            "GitHub SSH keys",
            "npm tokens",
            "AWS access keys (AKIA)",
            "GCP service account keys",
            "Azure service principal credentials",
            "Discord webhooks",
            "API keys in .env files",
            "Database credentials",
            "CI/CD runner tokens",
            "Docker registry credentials",
            "Cloud provider API keys"
        ]
        
        print(f"{Colors.BOLD}Immediately revoke and rotate:{Colors.END}\n")
        for i, cred in enumerate(credentials, 1):
            print(f"  {i}. {cred}")
        
        print(f"\n{Colors.YELLOW}⚠️  Treat EVERY credential on the compromised machine as compromised{Colors.END}")
        print(f"{Colors.YELLOW}⚠️  Check GitHub for unauthorized repositories and runners{Colors.END}")
        print(f"{Colors.YELLOW}⚠️  Review cloud provider access logs for suspicious activity{Colors.END}")
    
    def github_audit_checklist(self):
        """Display GitHub audit checklist"""
        self.print_header("GitHub Audit Checklist")
        
        checks = [
            "Check for new public repositories with suspicious names",
            "Review repository creation history",
            "Check for unauthorized commits from unusual IPs",
            "Review force pushes you didn't initiate",
            "Audit workflow files for suspicious changes",
            "Check for unauthorized self-hosted runner registrations",
            "Review GitHub Actions logs for suspicious activity",
            "Check for unauthorized package publishing events",
            "Review organization member access",
            "Check for new SSH keys or deploy keys"
        ]
        
        print(f"{Colors.BOLD}GitHub Security Checks:{Colors.END}\n")
        for i, check in enumerate(checks, 1):
            print(f"  {i}. {check}")
        
        print(f"\n{Colors.BLUE}GitHub API commands:{Colors.END}")
        print("  gh repo list --limit 1000")
        print("  gh api /user/repos --jq '.[] | select(.name | test(\"shai|hulud\"; \"i\"))'")
        print("  gh api /orgs/{org}/actions/runners")
    
    def hardening_measures(self):
        """Display and optionally apply hardening measures"""
        self.print_header("Long-Term Hardening Measures")
        
        measures = [
            {
                'title': 'Disable npm lifecycle scripts',
                'command': 'npm config set ignore-scripts true',
                'description': 'Prevents preinstall/postinstall scripts from running'
            },
            {
                'title': 'Pin exact package versions',
                'command': None,
                'description': 'Use exact versions in package.json, avoid ^ and ~ operators'
            },
            {
                'title': 'Enable GitHub security features',
                'command': None,
                'description': 'Enable 2FA, branch protection, secret scanning, dependency review'
            },
            {
                'title': 'Use short-lived tokens',
                'command': None,
                'description': 'Prefer GitHub OIDC for CI, rotate tokens every 30-90 days'
            }
        ]
        
        print(f"{Colors.BOLD}Recommended Hardening Measures:{Colors.END}\n")
        for i, measure in enumerate(measures, 1):
            print(f"{i}. {Colors.BOLD}{measure['title']}{Colors.END}")
            print(f"   {measure['description']}")
            if measure['command']:
                print(f"   {Colors.CYAN}Command: {measure['command']}{Colors.END}")
                if self.confirm_action(f"Apply '{measure['title']}'?"):
                    try:
                        result = subprocess.run(measure['command'].split(), 
                                              capture_output=True, 
                                              text=True, 
                                              timeout=30)
                        if result.returncode == 0:
                            self.print_success(f"Applied: {measure['title']}")
                        else:
                            self.print_warning(f"Command returned: {result.stderr}")
                    except Exception as e:
                        self.print_error(f"Error applying measure: {e}")
            print()
    
    def emergency_checklist(self):
        """Display emergency response checklist"""
        self.print_header("Emergency Response Checklist")
        
        checklist = [
            ("Scan for IOCs", "Run full detection scan"),
            ("Stop all CI/CD", "Disable GitHub Actions and automation"),
            ("Revoke ALL credentials", "GitHub PATs, npm tokens, cloud keys"),
            ("Disable publishing", "Disable GitHub Actions & npm publishing"),
            ("Purge caches", "Remove node_modules and npm cache"),
            ("Remove IOC files", "Delete all malicious files"),
            ("Rebuild machines", "Reinstall OS on compromised machines"),
            ("Restore from backups", "Use verified pre-infection backups"),
            ("Regenerate dependencies", "Safely reinstall with verified packages"),
            ("Re-enable securely", "Re-enable CI/CD with new credentials"),
            ("Implement hardening", "Apply long-term security measures")
        ]
        
        print(f"{Colors.BOLD}Emergency Response Steps:{Colors.END}\n")
        for i, (step, description) in enumerate(checklist, 1):
            status = "☐"
            print(f"  {status} {i}. {Colors.BOLD}{step}{Colors.END}")
            print(f"     {description}")
    
    def run_remediation(self):
        """Run interactive remediation"""
        self.print_header("🛡️ Shai-Hulud 2.0 Remediation")
        
        total_findings = sum(len(v) for v in self.detector.findings.values())
        
        if total_findings == 0:
            self.print_success("No findings detected. System appears clean.")
            if self.confirm_action("Would you like to see hardening measures anyway?"):
                self.hardening_measures()
            return
        
        self.print_warning(f"Found {total_findings} security finding(s)")
        
        # Show emergency checklist
        self.emergency_checklist()
        
        if self.confirm_action("\nProceed with automated remediation?"):
            self.remove_malicious_files()
            self.clean_npm_environment()
            self.fix_package_json()
            self.remove_compromised_packages()
            self.remediate_git_issues()
        
        # Show checklists
        self.credential_rotation_checklist()
        self.github_audit_checklist()
        
        if self.confirm_action("\nShow hardening measures?"):
            self.hardening_measures()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='🛡️ Shai-Hulud 2.0 Detection, Recovery, and Remediation Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  python shai_hulud_recovery.py --scan .

  # Scan specific directory and run remediation
  python shai_hulud_recovery.py --scan /path/to/project --remediate

  # Non-interactive mode (for CI/CD)
  python shai_hulud_recovery.py --scan . --remediate --non-interactive

  # Only detection, no remediation
  python shai_hulud_recovery.py --scan . --detect-only
        """
    )
    
    parser.add_argument('--scan', '-s', 
                       type=str, 
                       default='.',
                       help='Path to scan (default: current directory)')
    
    parser.add_argument('--remediate', '-r',
                       action='store_true',
                       help='Run remediation after detection')
    
    parser.add_argument('--detect-only', '-d',
                       action='store_true',
                       help='Only run detection, skip remediation')
    
    parser.add_argument('--non-interactive', '-n',
                       action='store_true',
                       help='Non-interactive mode (auto-confirm actions)')
    
    parser.add_argument('--quiet', '-q',
                       action='store_true',
                       help='Quiet mode (less output)')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = ShaiHuludDetector(scan_path=args.scan, verbose=not args.quiet)
    
    # Run detection
    report = detector.run_full_scan()
    
    # Run remediation if requested
    if args.remediate and not args.detect_only:
        remediator = ShaiHuludRemediator(
            detector=detector,
            interactive=not args.non_interactive
        )
        remediator.run_remediation()
    
    # Exit with appropriate code
    if report['summary']['total_findings'] > 0:
        critical_count = report['summary']['critical']
        if critical_count > 0:
            sys.exit(2)  # Critical findings
        else:
            sys.exit(1)  # Non-critical findings
    else:
        sys.exit(0)  # No findings


if __name__ == '__main__':
    main()

