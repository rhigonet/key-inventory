#!/usr/bin/env python3
"""
Compliance Check Script
Validates keys against compliance frameworks (PCI DSS, SOX, GDPR, NIST)
"""

import os
import sys
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Set


class ComplianceChecker:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.compliance_results = {}
    
    def load_key_file(self, file_path: str) -> Dict[str, Any]:
        """Load and parse a key file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.errors.append(f"Could not load {file_path}: {e}")
            return {}
    
    def check_pci_compliance(self, data: Dict[str, Any], filename: str) -> Dict[str, Any]:
        """Check PCI DSS compliance requirements."""
        results = {
            "framework": "PCI DSS",
            "status": "compliant",
            "issues": [],
            "requirements_met": [],
            "requirements_failed": []
        }
        
        compliance = data.get('compliance', {})
        pci_scope = compliance.get('pci_scope', 'none')
        
        if pci_scope == 'none':
            results["status"] = "not_applicable"
            results["requirements_met"].append("Not in PCI scope")
            return results
        
        # PCI DSS Requirements
        
        # Requirement 3: Protect stored cardholder data
        if pci_scope == 'cardholder-data':
            technical = data.get('technical', {})
            
            # Check encryption requirements
            if technical.get('key_type') not in ['rsa', 'ec', 'symmetric']:
                results["issues"].append("PCI DSS Req 3.4: Strong cryptography required for cardholder data")
                results["requirements_failed"].append("Strong cryptography")
            else:
                results["requirements_met"].append("Strong cryptography")
            
            # Check key size for RSA
            if technical.get('key_type') == 'rsa':
                key_size = technical.get('key_size', 0)
                if key_size < 2048:
                    results["issues"].append("PCI DSS Req 3.4: RSA keys must be at least 2048 bits")
                    results["requirements_failed"].append("Minimum key size")
                else:
                    results["requirements_met"].append("Minimum key size")
        
        # Requirement 8: Access controls
        audit = data.get('audit', {})
        if not audit.get('access_logs_enabled', False):
            results["issues"].append("PCI DSS Req 8.2: Access logging must be enabled")
            results["requirements_failed"].append("Access logging")
        else:
            results["requirements_met"].append("Access logging")
        
        # Requirement 10: Audit trails
        if not audit.get('usage_tracking_enabled', False):
            results["issues"].append("PCI DSS Req 10.1: Usage tracking must be enabled")
            results["requirements_failed"].append("Usage tracking")
        else:
            results["requirements_met"].append("Usage tracking")
        
        # Key rotation requirements
        rotation_days = data.get('rotation_interval_days', 0)
        if pci_scope == 'cardholder-data' and rotation_days > 365:
            results["issues"].append("PCI DSS Best Practice: Keys protecting cardholder data should rotate annually")
            results["requirements_failed"].append("Key rotation frequency")
        else:
            results["requirements_met"].append("Key rotation frequency")
        
        if results["issues"]:
            results["status"] = "non_compliant"
        
        return results
    
    def check_sox_compliance(self, data: Dict[str, Any], filename: str) -> Dict[str, Any]:
        """Check SOX compliance requirements."""
        results = {
            "framework": "SOX",
            "status": "compliant",
            "issues": [],
            "requirements_met": [],
            "requirements_failed": []
        }
        
        compliance = data.get('compliance', {})
        if not compliance.get('sox_applicable', False):
            results["status"] = "not_applicable"
            results["requirements_met"].append("Not subject to SOX")
            return results
        
        # SOX Requirements
        
        # Segregation of duties
        lifecycle = data.get('lifecycle', {})
        created_by = lifecycle.get('created_by')
        approved_by = lifecycle.get('approved_by')
        
        if created_by and approved_by and created_by == approved_by:
            results["issues"].append("SOX Req: Key creator and approver must be different (segregation of duties)")
            results["requirements_failed"].append("Segregation of duties")
        else:
            results["requirements_met"].append("Segregation of duties")
        
        # Audit trail requirements
        audit = data.get('audit', {})
        if not audit.get('access_logs_enabled', False):
            results["issues"].append("SOX Req: Access logging required for audit trail")
            results["requirements_failed"].append("Access logging")
        else:
            results["requirements_met"].append("Access logging")
        
        # Change management
        if not lifecycle.get('approved_by'):
            results["issues"].append("SOX Req: All key changes must be approved")
            results["requirements_failed"].append("Change approval")
        else:
            results["requirements_met"].append("Change approval")
        
        # Documentation requirements
        if not data.get('purpose'):
            results["issues"].append("SOX Req: Business purpose must be documented")
            results["requirements_failed"].append("Documentation")
        else:
            results["requirements_met"].append("Documentation")
        
        if results["issues"]:
            results["status"] = "non_compliant"
        
        return results
    
    def check_gdpr_compliance(self, data: Dict[str, Any], filename: str) -> Dict[str, Any]:
        """Check GDPR compliance requirements."""
        results = {
            "framework": "GDPR",
            "status": "compliant",
            "issues": [],
            "requirements_met": [],
            "requirements_failed": []
        }
        
        compliance = data.get('compliance', {})
        if not compliance.get('gdpr_applicable', False):
            results["status"] = "not_applicable"
            results["requirements_met"].append("Not processing personal data")
            return results
        
        # GDPR Requirements
        
        # Data protection by design
        technical = data.get('technical', {})
        if not technical.get('high_availability', False):
            results["warnings"] = results.get("warnings", [])
            results["warnings"].append("GDPR Best Practice: Consider high availability for personal data protection")
        
        # Retention period
        retention_days = compliance.get('retention_period_days')
        if not retention_days:
            results["issues"].append("GDPR Req: Data retention period must be specified")
            results["requirements_failed"].append("Retention period")
        else:
            results["requirements_met"].append("Retention period specified")
        
        # Encryption requirements
        if technical.get('key_type') not in ['rsa', 'ec', 'symmetric']:
            results["issues"].append("GDPR Req: Strong encryption required for personal data")
            results["requirements_failed"].append("Encryption")
        else:
            results["requirements_met"].append("Strong encryption")
        
        # Access controls
        audit = data.get('audit', {})
        if not audit.get('access_logs_enabled', False):
            results["issues"].append("GDPR Req: Access logging required for personal data")
            results["requirements_failed"].append("Access logging")
        else:
            results["requirements_met"].append("Access logging")
        
        if results["issues"]:
            results["status"] = "non_compliant"
        
        return results
    
    def check_nist_compliance(self, data: Dict[str, Any], filename: str) -> Dict[str, Any]:
        """Check NIST Cybersecurity Framework compliance."""
        results = {
            "framework": "NIST CSF",
            "status": "compliant",
            "issues": [],
            "requirements_met": [],
            "requirements_failed": []
        }
        
        compliance = data.get('compliance', {})
        nist_class = compliance.get('nist_classification', 'internal')
        
        # NIST Requirements based on classification
        
        # Identify (ID)
        if not data.get('owner'):
            results["issues"].append("NIST ID.AM: Asset owner must be identified")
            results["requirements_failed"].append("Asset identification")
        else:
            results["requirements_met"].append("Asset identification")
        
        # Protect (PR)
        technical = data.get('technical', {})
        operational = data.get('operational', {})
        
        if nist_class in ['confidential', 'secret', 'top-secret']:
            if not technical.get('high_availability', False):
                results["issues"].append("NIST PR.IP: High availability required for classified data")
                results["requirements_failed"].append("High availability")
            else:
                results["requirements_met"].append("High availability")
        
        # Detect (DE)
        if not operational.get('monitoring_enabled', False):
            results["issues"].append("NIST DE.CM: Monitoring must be enabled")
            results["requirements_failed"].append("Monitoring")
        else:
            results["requirements_met"].append("Monitoring")
        
        # Respond (RS)
        if not operational.get('emergency_revocation_enabled', False):
            results["issues"].append("NIST RS.MI: Emergency response capability required")
            results["requirements_failed"].append("Emergency response")
        else:
            results["requirements_met"].append("Emergency response")
        
        # Recover (RC)
        if nist_class in ['secret', 'top-secret'] and not technical.get('backup_location'):
            results["issues"].append("NIST RC.RP: Backup location required for high-classification keys")
            results["requirements_failed"].append("Backup and recovery")
        else:
            results["requirements_met"].append("Backup and recovery")
        
        # Key rotation based on classification
        rotation_days = data.get('rotation_interval_days', 0)
        max_rotation_days = {
            'top-secret': 90,
            'secret': 180,
            'confidential': 365,
            'internal': 1095
        }
        
        max_days = max_rotation_days.get(nist_class, 1095)
        if rotation_days > max_days:
            results["issues"].append(f"NIST Best Practice: {nist_class} keys should rotate every {max_days} days or less")
            results["requirements_failed"].append("Rotation frequency")
        else:
            results["requirements_met"].append("Rotation frequency")
        
        if results["issues"]:
            results["status"] = "non_compliant"
        
        return results
    
    def check_file_compliance(self, file_path: str) -> Dict[str, Any]:
        """Check compliance for a single file."""
        filename = os.path.basename(file_path)
        data = self.load_key_file(file_path)
        
        if not data:
            return {"error": f"Could not load {filename}"}
        
        file_results = {
            "file": filename,
            "key_id": data.get('key_id', 'unknown'),
            "alias": data.get('alias', 'unknown'),
            "frameworks": {}
        }
        
        # Check each compliance framework
        file_results["frameworks"]["pci_dss"] = self.check_pci_compliance(data, filename)
        file_results["frameworks"]["sox"] = self.check_sox_compliance(data, filename)
        file_results["frameworks"]["gdpr"] = self.check_gdpr_compliance(data, filename)
        file_results["frameworks"]["nist"] = self.check_nist_compliance(data, filename)
        
        # Overall compliance status
        overall_status = "compliant"
        for framework_results in file_results["frameworks"].values():
            if framework_results.get("status") == "non_compliant":
                overall_status = "non_compliant"
                break
        
        file_results["overall_status"] = overall_status
        
        return file_results
    
    def generate_compliance_report(self, results: List[Dict[str, Any]]) -> str:
        """Generate a formatted compliance report."""
        report = ["## 📋 Compliance Check Results\n"]
        
        compliant_count = 0
        non_compliant_count = 0
        not_applicable_count = 0
        
        for result in results:
            if "error" in result:
                report.append(f"❌ **{result['file']}**: {result['error']}\n")
                continue
            
            status = result["overall_status"]
            if status == "compliant":
                compliant_count += 1
                status_icon = "✅"
            else:
                non_compliant_count += 1
                status_icon = "❌"
            
            report.append(f"### {status_icon} {result['file']} ({result['alias']})\n")
            
            for framework, framework_results in result["frameworks"].items():
                framework_name = framework_results["framework"]
                framework_status = framework_results["status"]
                
                if framework_status == "not_applicable":
                    report.append(f"- **{framework_name}**: Not applicable\n")
                    continue
                
                if framework_status == "compliant":
                    report.append(f"- **{framework_name}**: ✅ Compliant\n")
                else:
                    report.append(f"- **{framework_name}**: ❌ Non-compliant\n")
                
                if framework_results.get("issues"):
                    for issue in framework_results["issues"]:
                        report.append(f"  - ⚠️ {issue}\n")
            
            report.append("\n")
        
        # Summary
        report.insert(1, f"**Summary:** {compliant_count} compliant, {non_compliant_count} non-compliant\n\n")
        
        return "".join(report)


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: compliance-check.py <file1> [file2] ...")
        sys.exit(1)
    
    files_to_check = [f for f in sys.argv[1:] if f.strip()]
    
    if not files_to_check:
        print("No files to check")
        sys.exit(0)
    
    print(f"Checking compliance for {len(files_to_check)} files...")
    
    checker = ComplianceChecker()
    results = []
    
    for file_path in files_to_check:
        print(f"Checking {file_path}...")
        result = checker.check_file_compliance(file_path)
        results.append(result)
    
    # Generate report
    report = checker.generate_compliance_report(results)
    
    # Write results to file for GitHub Actions
    with open('compliance-results.txt', 'w') as f:
        f.write(report)
    
    # Check if any files are non-compliant
    non_compliant = any(r.get("overall_status") == "non_compliant" for r in results)
    
    print(f"\nCompliance Check Summary:")
    print(f"Files checked: {len(files_to_check)}")
    
    if non_compliant:
        print("❌ Some files are non-compliant")
        sys.exit(1)
    else:
        print("✅ All files are compliant!")
        sys.exit(0)


if __name__ == "__main__":
    main()