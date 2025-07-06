#!/usr/bin/env python3
"""
Compliance Report Generator
Generates comprehensive compliance reports for all frameworks
"""

import os
import sys
import json
import yaml
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Set
from collections import defaultdict


class ComplianceReportGenerator:
    def __init__(self, inventory_dir: str = "inventory", output_dir: str = "reports"):
        self.inventory_dir = Path(inventory_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.frameworks = {
            'pci_dss': 'PCI DSS',
            'sox': 'SOX',
            'gdpr': 'GDPR', 
            'nist': 'NIST CSF'
        }
    
    def load_all_keys(self) -> List[Dict[str, Any]]:
        """Load all key definitions from inventory."""
        keys = []
        
        if not self.inventory_dir.exists():
            print(f"Warning: Inventory directory {self.inventory_dir} does not exist")
            return keys
        
        yaml_files = list(self.inventory_dir.glob('*.yaml')) + list(self.inventory_dir.glob('*.yml'))
        
        for file_path in yaml_files:
            try:
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data:
                        data['_file_path'] = str(file_path)
                        keys.append(data)
            except Exception as e:
                print(f"Warning: Could not load {file_path}: {e}")
        
        return keys
    
    def is_pci_applicable(self, key: Dict[str, Any]) -> bool:
        """Check if key is subject to PCI DSS requirements."""
        compliance = key.get('compliance', {})
        return compliance.get('pci_scope', 'none') != 'none'
    
    def is_sox_applicable(self, key: Dict[str, Any]) -> bool:
        """Check if key is subject to SOX requirements."""
        compliance = key.get('compliance', {})
        return compliance.get('sox_applicable', False)
    
    def is_gdpr_applicable(self, key: Dict[str, Any]) -> bool:
        """Check if key is subject to GDPR requirements."""
        compliance = key.get('compliance', {})
        return compliance.get('gdpr_applicable', False)
    
    def check_pci_compliance(self, key: Dict[str, Any]) -> Dict[str, Any]:
        """Check PCI DSS compliance for a key."""
        if not self.is_pci_applicable(key):
            return {
                'applicable': False,
                'status': 'not_applicable',
                'score': 100,
                'requirements': {},
                'violations': []
            }
        
        violations = []
        requirements = {}
        
        # Requirement 3.4: Strong cryptography
        technical = key.get('technical', {})
        key_type = technical.get('key_type')
        key_size = technical.get('key_size', 0)
        
        if key_type not in ['rsa', 'ec', 'symmetric']:
            violations.append("PCI DSS 3.4: Weak cryptographic algorithm")
            requirements['strong_crypto'] = False
        else:
            requirements['strong_crypto'] = True
        
        # RSA key size requirement
        if key_type == 'rsa' and key_size < 2048:
            violations.append("PCI DSS 3.4: RSA key size must be at least 2048 bits")
            requirements['min_key_size'] = False
        else:
            requirements['min_key_size'] = True
        
        # Requirement 8: Access controls
        audit = key.get('audit', {})
        if not audit.get('access_logs_enabled', False):
            violations.append("PCI DSS 8.2: Access logging must be enabled")
            requirements['access_logging'] = False
        else:
            requirements['access_logging'] = True
        
        # Requirement 10: Audit trails
        if not audit.get('usage_tracking_enabled', False):
            violations.append("PCI DSS 10.1: Usage tracking must be enabled")
            requirements['usage_tracking'] = False
        else:
            requirements['usage_tracking'] = True
        
        # Key rotation for cardholder data
        compliance = key.get('compliance', {})
        rotation_days = key.get('rotation_interval_days', 0)
        
        if compliance.get('pci_scope') == 'cardholder-data' and rotation_days > 365:
            violations.append("PCI DSS Best Practice: Annual rotation required for cardholder data")
            requirements['rotation_frequency'] = False
        else:
            requirements['rotation_frequency'] = True
        
        # Calculate compliance score
        total_reqs = len(requirements)
        passed_reqs = sum(1 for passed in requirements.values() if passed)
        score = (passed_reqs / total_reqs * 100) if total_reqs > 0 else 100
        
        return {
            'applicable': True,
            'status': 'compliant' if len(violations) == 0 else 'non_compliant',
            'score': round(score, 2),
            'requirements': requirements,
            'violations': violations
        }
    
    def check_sox_compliance(self, key: Dict[str, Any]) -> Dict[str, Any]:
        """Check SOX compliance for a key."""
        if not self.is_sox_applicable(key):
            return {
                'applicable': False,
                'status': 'not_applicable',
                'score': 100,
                'requirements': {},
                'violations': []
            }
        
        violations = []
        requirements = {}
        
        # Segregation of duties
        lifecycle = key.get('lifecycle', {})
        created_by = lifecycle.get('created_by')
        approved_by = lifecycle.get('approved_by')
        
        if created_by and approved_by and created_by == approved_by:
            violations.append("SOX: Creator and approver must be different")
            requirements['segregation_of_duties'] = False
        else:
            requirements['segregation_of_duties'] = True
        
        # Audit trails
        audit = key.get('audit', {})
        if not audit.get('access_logs_enabled', False):
            violations.append("SOX: Access logging required")
            requirements['audit_trails'] = False
        else:
            requirements['audit_trails'] = True
        
        # Change management
        if not approved_by:
            violations.append("SOX: All changes must be approved")
            requirements['change_approval'] = False
        else:
            requirements['change_approval'] = True
        
        # Documentation
        if not key.get('purpose'):
            violations.append("SOX: Business purpose must be documented")
            requirements['documentation'] = False
        else:
            requirements['documentation'] = True
        
        # Calculate compliance score
        total_reqs = len(requirements)
        passed_reqs = sum(1 for passed in requirements.values() if passed)
        score = (passed_reqs / total_reqs * 100) if total_reqs > 0 else 100
        
        return {
            'applicable': True,
            'status': 'compliant' if len(violations) == 0 else 'non_compliant',
            'score': round(score, 2),
            'requirements': requirements,
            'violations': violations
        }
    
    def check_gdpr_compliance(self, key: Dict[str, Any]) -> Dict[str, Any]:
        """Check GDPR compliance for a key."""
        if not self.is_gdpr_applicable(key):
            return {
                'applicable': False,
                'status': 'not_applicable',
                'score': 100,
                'requirements': {},
                'violations': []
            }
        
        violations = []
        requirements = {}
        
        # Data retention
        compliance = key.get('compliance', {})
        if not compliance.get('retention_period_days'):
            violations.append("GDPR: Data retention period must be specified")
            requirements['retention_period'] = False
        else:
            requirements['retention_period'] = True
        
        # Encryption
        technical = key.get('technical', {})
        if technical.get('key_type') not in ['rsa', 'ec', 'symmetric']:
            violations.append("GDPR: Strong encryption required")
            requirements['encryption'] = False
        else:
            requirements['encryption'] = True
        
        # Access controls
        audit = key.get('audit', {})
        if not audit.get('access_logs_enabled', False):
            violations.append("GDPR: Access logging required")
            requirements['access_controls'] = False
        else:
            requirements['access_controls'] = True
        
        # Calculate compliance score
        total_reqs = len(requirements)
        passed_reqs = sum(1 for passed in requirements.values() if passed)
        score = (passed_reqs / total_reqs * 100) if total_reqs > 0 else 100
        
        return {
            'applicable': True,
            'status': 'compliant' if len(violations) == 0 else 'non_compliant',
            'score': round(score, 2),
            'requirements': requirements,
            'violations': violations
        }
    
    def check_nist_compliance(self, key: Dict[str, Any]) -> Dict[str, Any]:
        """Check NIST CSF compliance for a key."""
        violations = []
        requirements = {}
        
        compliance = key.get('compliance', {})
        nist_class = compliance.get('nist_classification', 'internal')
        
        # Identify (ID)
        if not key.get('owner'):
            violations.append("NIST ID.AM: Asset owner must be identified")
            requirements['asset_identification'] = False
        else:
            requirements['asset_identification'] = True
        
        # Protect (PR)
        technical = key.get('technical', {})
        operational = key.get('operational', {})
        
        if nist_class in ['confidential', 'secret', 'top-secret']:
            if not technical.get('high_availability', False):
                violations.append("NIST PR.IP: High availability required for classified data")
                requirements['high_availability'] = False
            else:
                requirements['high_availability'] = True
        else:
            requirements['high_availability'] = True  # Not required for lower classifications
        
        # Detect (DE)
        if not operational.get('monitoring_enabled', False):
            violations.append("NIST DE.CM: Monitoring must be enabled")
            requirements['monitoring'] = False
        else:
            requirements['monitoring'] = True
        
        # Respond (RS)
        if not operational.get('emergency_revocation_enabled', False):
            violations.append("NIST RS.MI: Emergency response capability required")
            requirements['emergency_response'] = False
        else:
            requirements['emergency_response'] = True
        
        # Recover (RC)
        if nist_class in ['secret', 'top-secret'] and not technical.get('backup_location'):
            violations.append("NIST RC.RP: Backup required for high-classification keys")
            requirements['backup_recovery'] = False
        else:
            requirements['backup_recovery'] = True
        
        # Key rotation based on classification
        rotation_days = key.get('rotation_interval_days', 0)
        max_rotation_days = {
            'top-secret': 90,
            'secret': 180,
            'confidential': 365,
            'internal': 1095
        }
        
        max_days = max_rotation_days.get(nist_class, 1095)
        if rotation_days > max_days:
            violations.append(f"NIST: {nist_class} keys should rotate every {max_days} days")
            requirements['rotation_frequency'] = False
        else:
            requirements['rotation_frequency'] = True
        
        # Calculate compliance score
        total_reqs = len(requirements)
        passed_reqs = sum(1 for passed in requirements.values() if passed)
        score = (passed_reqs / total_reqs * 100) if total_reqs > 0 else 100
        
        return {
            'applicable': True,
            'status': 'compliant' if len(violations) == 0 else 'non_compliant',
            'score': round(score, 2),
            'requirements': requirements,
            'violations': violations
        }
    
    def generate_key_compliance_report(self, key: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance report for a single key."""
        return {
            'key_id': key.get('key_id'),
            'alias': key.get('alias'),
            'environment': key.get('environment'),
            'owner': key.get('owner'),
            'frameworks': {
                'pci_dss': self.check_pci_compliance(key),
                'sox': self.check_sox_compliance(key),
                'gdpr': self.check_gdpr_compliance(key),
                'nist': self.check_nist_compliance(key)
            }
        }
    
    def generate_summary_report(self, key_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary compliance report."""
        summary = {
            'total_keys': len(key_reports),
            'frameworks': {}
        }
        
        for framework in self.frameworks:
            applicable_keys = [
                report for report in key_reports 
                if report['frameworks'][framework]['applicable']
            ]
            
            if applicable_keys:
                compliant_keys = [
                    report for report in applicable_keys
                    if report['frameworks'][framework]['status'] == 'compliant'
                ]
                
                total_score = sum(
                    report['frameworks'][framework]['score'] 
                    for report in applicable_keys
                )
                avg_score = total_score / len(applicable_keys)
                
                summary['frameworks'][framework] = {
                    'name': self.frameworks[framework],
                    'applicable_keys': len(applicable_keys),
                    'compliant_keys': len(compliant_keys),
                    'non_compliant_keys': len(applicable_keys) - len(compliant_keys),
                    'compliance_rate': round((len(compliant_keys) / len(applicable_keys)) * 100, 2),
                    'average_score': round(avg_score, 2)
                }
            else:
                summary['frameworks'][framework] = {
                    'name': self.frameworks[framework],
                    'applicable_keys': 0,
                    'compliant_keys': 0,
                    'non_compliant_keys': 0,
                    'compliance_rate': 100.0,
                    'average_score': 100.0
                }
        
        return summary
    
    def generate_html_report(self, summary: Dict[str, Any], key_reports: List[Dict[str, Any]]) -> str:
        """Generate HTML compliance report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Key Inventory Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .framework {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .compliant {{ background: #d4edda; }}
        .non-compliant {{ background: #f8d7da; }}
        .not-applicable {{ background: #f0f0f0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f0f0f0; }}
        .score {{ font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Key Inventory Compliance Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p>Total Keys: {summary['total_keys']}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Compliance Summary</h2>
        <table>
            <tr>
                <th>Framework</th>
                <th>Applicable Keys</th>
                <th>Compliant</th>
                <th>Non-Compliant</th>
                <th>Compliance Rate</th>
                <th>Average Score</th>
            </tr>
"""
        
        for framework, data in summary['frameworks'].items():
            html += f"""
            <tr>
                <td>{data['name']}</td>
                <td>{data['applicable_keys']}</td>
                <td style="color: green;">{data['compliant_keys']}</td>
                <td style="color: red;">{data['non_compliant_keys']}</td>
                <td class="score">{data['compliance_rate']}%</td>
                <td class="score">{data['average_score']}</td>
            </tr>
"""
        
        html += """
        </table>
    </div>
    
    <div>
        <h2>🔍 Detailed Key Reports</h2>
"""
        
        for report in key_reports:
            html += f"""
        <div class="framework">
            <h3>Key: {report['alias']} ({report['key_id']})</h3>
            <p><strong>Environment:</strong> {report['environment']} | <strong>Owner:</strong> {report['owner']}</p>
            
            <table>
                <tr>
                    <th>Framework</th>
                    <th>Status</th>
                    <th>Score</th>
                    <th>Violations</th>
                </tr>
"""
            
            for framework, compliance in report['frameworks'].items():
                if compliance['applicable']:
                    status_class = 'compliant' if compliance['status'] == 'compliant' else 'non-compliant'
                    violations = '<br>'.join(compliance['violations']) if compliance['violations'] else 'None'
                else:
                    status_class = 'not-applicable'
                    violations = 'Not applicable'
                
                html += f"""
                <tr class="{status_class}">
                    <td>{self.frameworks[framework]}</td>
                    <td>{compliance['status'].replace('_', ' ').title()}</td>
                    <td>{compliance['score']}%</td>
                    <td>{violations}</td>
                </tr>
"""
            
            html += """
            </table>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def generate_compliance_report(self, output_formats: List[str] = None) -> bool:
        """Generate complete compliance report."""
        if output_formats is None:
            output_formats = ['json', 'html']
        
        print("🔍 Loading key inventory...")
        keys = self.load_all_keys()
        
        if not keys:
            print("❌ No keys found in inventory")
            return False
        
        print(f"📊 Analyzing compliance for {len(keys)} keys...")
        
        key_reports = []
        for key in keys:
            report = self.generate_key_compliance_report(key)
            key_reports.append(report)
        
        summary = self.generate_summary_report(key_reports)
        
        timestamp = datetime.now().isoformat()
        
        complete_report = {
            'metadata': {
                'generated_at': timestamp,
                'total_keys': len(keys),
                'frameworks_checked': list(self.frameworks.keys())
            },
            'summary': summary,
            'detailed_reports': key_reports
        }
        
        # Save reports in requested formats
        success = True
        
        if 'json' in output_formats:
            json_file = self.output_dir / f"compliance-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            try:
                with open(json_file, 'w') as f:
                    json.dump(complete_report, f, indent=2)
                print(f"✅ JSON report saved: {json_file}")
            except Exception as e:
                print(f"❌ Failed to save JSON report: {e}")
                success = False
        
        if 'html' in output_formats:
            html_content = self.generate_html_report(summary, key_reports)
            html_file = self.output_dir / f"compliance-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
            try:
                with open(html_file, 'w') as f:
                    f.write(html_content)
                print(f"✅ HTML report saved: {html_file}")
            except Exception as e:
                print(f"❌ Failed to save HTML report: {e}")
                success = False
        
        # Print summary to console
        print(f"\n📋 Compliance Summary:")
        for framework, data in summary['frameworks'].items():
            print(f"{data['name']}: {data['compliance_rate']}% compliant ({data['compliant_keys']}/{data['applicable_keys']})")
        
        return success


def main():
    parser = argparse.ArgumentParser(description='Generate compliance reports for key inventory')
    parser.add_argument('--inventory-dir', default='inventory', help='Inventory directory')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    parser.add_argument('--format', choices=['json', 'html'], action='append', help='Output format(s)')
    parser.add_argument('--framework', choices=['pci_dss', 'sox', 'gdpr', 'nist'], action='append', 
                       help='Specific framework(s) to check')
    
    args = parser.parse_args()
    
    output_formats = args.format or ['json', 'html']
    
    generator = ComplianceReportGenerator(args.inventory_dir, args.output_dir)
    success = generator.generate_compliance_report(output_formats)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()