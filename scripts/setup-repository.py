#!/usr/bin/env python3
"""
Repository Setup Script
Sets up the key inventory repository with all required configurations
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Any


class RepositorySetup:
    def __init__(self, owner: str, repo: str, org: str = None):
        self.owner = owner
        self.repo = repo
        self.org = org or owner
        self.errors = []
        self.warnings = []
    
    def run_gh_command(self, cmd: List[str]) -> bool:
        """Run a GitHub CLI command."""
        try:
            print(f"Running: gh {' '.join(cmd)}")
            result = subprocess.run(['gh'] + cmd, capture_output=True, text=True, check=True)
            if result.stdout:
                print(f"Output: {result.stdout.strip()}")
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: gh {' '.join(cmd)}"
            if e.stderr:
                error_msg += f"\nError: {e.stderr.strip()}"
            self.errors.append(error_msg)
            print(f"❌ {error_msg}")
            return False
        except FileNotFoundError:
            self.errors.append("GitHub CLI (gh) is not installed or not in PATH")
            print("❌ GitHub CLI (gh) is not installed or not in PATH")
            return False
    
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met."""
        print("🔍 Checking prerequisites...")
        
        # Check if gh CLI is installed
        try:
            result = subprocess.run(['gh', '--version'], capture_output=True, text=True)
            print(f"✅ GitHub CLI found: {result.stdout.split()[2]}")
        except FileNotFoundError:
            self.errors.append("GitHub CLI (gh) is not installed")
            return False
        
        # Check if authenticated
        try:
            result = subprocess.run(['gh', 'auth', 'status'], capture_output=True, text=True)
            if "Logged in to github.com" in result.stderr:
                print("✅ GitHub CLI authenticated")
            else:
                self.errors.append("GitHub CLI not authenticated. Run 'gh auth login'")
                return False
        except subprocess.CalledProcessError:
            self.errors.append("GitHub CLI authentication check failed")
            return False
        
        return True
    
    def setup_teams(self) -> bool:
        """Create required teams in the organization."""
        print("\n👥 Setting up teams...")
        
        teams = [
            {
                "name": "key-inventory-admins",
                "description": "Key inventory administrators with full access to key management",
                "privacy": "closed"
            },
            {
                "name": "security-team",
                "description": "Security team with oversight and emergency access",
                "privacy": "closed"
            }
        ]
        
        success = True
        for team in teams:
            print(f"Creating team: {team['name']}")
            cmd = [
                'api', f'orgs/{self.org}/teams', '--method', 'POST',
                '--field', f'name={team["name"]}',
                '--field', f'description={team["description"]}',
                '--field', f'privacy={team["privacy"]}'
            ]
            
            if not self.run_gh_command(cmd):
                # Team might already exist, which is okay
                print(f"⚠️ Team {team['name']} might already exist")
        
        return success
    
    def setup_branch_protection(self) -> bool:
        """Set up branch protection rules."""
        print("\n🛡️ Setting up branch protection...")
        
        protection_config = {
            "required_status_checks": {
                "strict": True,
                "contexts": [
                    "validate-key-creation",
                    "security-scan",
                    "compliance-check",
                    "check-duplicates"
                ]
            },
            "enforce_admins": True,
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True
            },
            "restrictions": {
                "users": [],
                "teams": [],
                "apps": []
            }
        }
        
        cmd = [
            'api', f'repos/{self.owner}/{self.repo}/branches/main/protection',
            '--method', 'PUT',
            '--field', f'required_status_checks={json.dumps(protection_config["required_status_checks"])}',
            '--field', f'enforce_admins={str(protection_config["enforce_admins"]).lower()}',
            '--field', f'required_pull_request_reviews={json.dumps(protection_config["required_pull_request_reviews"])}',
            '--field', f'restrictions={json.dumps(protection_config["restrictions"])}'
        ]
        
        return self.run_gh_command(cmd)
    
    def setup_environments(self) -> bool:
        """Set up GitHub environments for deployments."""
        print("\n🌍 Setting up environments...")
        
        environments = [
            "key-provisioning",
            "key-deletion", 
            "key-rotation",
            "emergency-key-ops"
        ]
        
        success = True
        for env in environments:
            print(f"Creating environment: {env}")
            cmd = ['api', f'repos/{self.owner}/{self.repo}/environments/{env}', '--method', 'PUT']
            if not self.run_gh_command(cmd):
                success = False
        
        return success
    
    def setup_team_permissions(self) -> bool:
        """Set up team permissions for the repository."""
        print("\n🔐 Setting up team permissions...")
        
        team_permissions = [
            ("key-inventory-admins", "admin"),
            ("security-team", "push")
        ]
        
        success = True
        for team, permission in team_permissions:
            print(f"Setting {team} permission to {permission}")
            cmd = [
                'api', f'repos/{self.owner}/{self.repo}/teams/{team}',
                '--method', 'PUT',
                '--field', f'permission={permission}'
            ]
            if not self.run_gh_command(cmd):
                success = False
        
        return success
    
    def setup_repository_settings(self) -> bool:
        """Configure repository settings."""
        print("\n⚙️ Setting up repository settings...")
        
        settings = {
            "has_issues": True,
            "has_projects": False,
            "has_wiki": False,
            "has_pages": True,
            "delete_branch_on_merge": True,
            "allow_squash_merge": True,
            "allow_merge_commit": True,
            "allow_rebase_merge": False,
            "allow_auto_merge": False,
            "vulnerability_alerts": True,
            "automated_security_fixes": True
        }
        
        success = True
        for setting, value in settings.items():
            cmd = [
                'api', f'repos/{self.owner}/{self.repo}',
                '--method', 'PATCH',
                '--field', f'{setting}={str(value).lower()}'
            ]
            if not self.run_gh_command(cmd):
                success = False
        
        return success
    
    def create_initial_secrets(self) -> bool:
        """Create placeholders for repository secrets."""
        print("\n🔑 Setting up repository secrets placeholders...")
        
        secrets = [
            "AWS_REGION",
            "AZURE_TENANT_ID", 
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "SLACK_WEBHOOK_URL",
            "EMAIL_CONFIG",
            "PAGERDUTY_API_KEY",
            "SMS_CONFIG"
        ]
        
        print("Note: The following secrets need to be manually configured:")
        for secret in secrets:
            print(f"  - {secret}")
        
        print("\nTo set secrets, use:")
        print(f"gh secret set SECRET_NAME --repo {self.owner}/{self.repo}")
        
        return True
    
    def create_sample_files(self) -> bool:
        """Create sample configuration files."""
        print("\n📁 Creating sample configuration files...")
        
        # Create config directory if it doesn't exist
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        # Create emergency contacts file
        emergency_contacts = {
            "emergency_contacts": {
                "primary": {
                    "security_team": {
                        "email": "security-team@company.com",
                        "slack": "#security-alerts",
                        "pagerduty": "security-team-escalation",
                        "phone": "+1-555-SECURITY"
                    },
                    "key_inventory_admins": {
                        "email": "key-admins@company.com", 
                        "slack": "#key-inventory-admins",
                        "pagerduty": "key-admin-escalation",
                        "phone": "+1-555-KEY-ADMIN"
                    }
                }
            }
        }
        
        with open("config/emergency-contacts.yml", "w") as f:
            import yaml
            yaml.dump(emergency_contacts, f, default_flow_style=False)
        
        print("✅ Created config/emergency-contacts.yml")
        
        return True
    
    def run_setup(self) -> bool:
        """Run the complete setup process."""
        print("🚀 Starting Key Inventory Repository Setup")
        print(f"Repository: {self.owner}/{self.repo}")
        print(f"Organization: {self.org}")
        
        if not self.check_prerequisites():
            return False
        
        steps = [
            ("Creating teams", self.setup_teams),
            ("Setting up branch protection", self.setup_branch_protection),
            ("Creating environments", self.setup_environments),
            ("Configuring team permissions", self.setup_team_permissions),
            ("Configuring repository settings", self.setup_repository_settings),
            ("Setting up secrets placeholders", self.create_initial_secrets),
            ("Creating sample files", self.create_sample_files)
        ]
        
        failed_steps = []
        for step_name, step_func in steps:
            print(f"\n{'='*60}")
            try:
                if step_func():
                    print(f"✅ {step_name} completed successfully")
                else:
                    print(f"❌ {step_name} failed")
                    failed_steps.append(step_name)
            except Exception as e:
                print(f"❌ {step_name} failed with exception: {e}")
                failed_steps.append(step_name)
        
        # Summary
        print(f"\n{'='*60}")
        print("🎯 Setup Summary")
        print(f"{'='*60}")
        
        if failed_steps:
            print(f"❌ Failed steps: {len(failed_steps)}")
            for step in failed_steps:
                print(f"  - {step}")
        else:
            print("✅ All steps completed successfully!")
        
        if self.errors:
            print(f"\n⚠️ Errors encountered: {len(self.errors)}")
            for error in self.errors:
                print(f"  - {error}")
        
        if self.warnings:
            print(f"\n⚠️ Warnings: {len(self.warnings)}")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        print(f"\n📋 Next Steps:")
        print("1. Configure repository secrets with actual values")
        print("2. Add team members to key-inventory-admins and security-team")
        print("3. Review and test GitHub Actions workflows")
        print("4. Create your first key definition in inventory/")
        print("5. Enable GitHub Pages for the documentation")
        
        return len(failed_steps) == 0


def main():
    parser = argparse.ArgumentParser(description="Set up key inventory repository")
    parser.add_argument("--owner", required=True, help="Repository owner")
    parser.add_argument("--repo", required=True, help="Repository name")
    parser.add_argument("--org", help="Organization name (defaults to owner)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("🧪 DRY RUN MODE - No changes will be made")
        print(f"Would set up repository: {args.owner}/{args.repo}")
        return
    
    setup = RepositorySetup(args.owner, args.repo, args.org)
    success = setup.run_setup()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()