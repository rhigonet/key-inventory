#!/usr/bin/env python3
"""
Approval Checklist Generator
Generates approval checklists for key creation requests
"""

import os
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


def load_key_file(file_path: str) -> Dict[str, Any]:
    """Load and parse a key file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not load {file_path}: {e}")
        return {}


def generate_checklist_for_key(data: Dict[str, Any], filename: str) -> str:
    """Generate approval checklist for a single key."""
    checklist = []
    
    # Basic information
    key_id = data.get('key_id', 'Unknown')
    alias = data.get('alias', 'Unknown')
    environment = data.get('environment', 'Unknown')
    owner = data.get('owner', 'Unknown')
    purpose = data.get('purpose', 'Unknown')
    
    checklist.append(f"### 🔑 Key: {alias} ({key_id})\n")
    checklist.append(f"**File:** `{filename}`")
    checklist.append(f"**Environment:** {environment}")
    checklist.append(f"**Owner:** {owner}")
    checklist.append(f"**Purpose:** {purpose}\n")
    
    # Approval checklist items
    checklist.append("#### ✅ Approval Checklist\n")
    checklist.append("**Technical Review:**")
    checklist.append("- [ ] Key ID follows UUID v4 format")
    checklist.append("- [ ] Alias is descriptive and follows naming conventions")
    checklist.append("- [ ] Environment is correctly specified")
    checklist.append("- [ ] Key store location is valid and accessible")
    
    # Technical-specific checks
    technical = data.get('technical', {})
    if technical:
        key_type = technical.get('key_type')
        if key_type:
            checklist.append(f"- [ ] Key type ({key_type}) is appropriate for the use case")
        
        key_size = technical.get('key_size')
        if key_size:
            checklist.append(f"- [ ] Key size ({key_size}) meets security requirements")
        
        if technical.get('high_availability'):
            checklist.append("- [ ] High availability configuration is justified")
        
        if technical.get('backup_location'):
            checklist.append("- [ ] Backup location is properly configured")
    
    checklist.append("\n**Business Review:**")
    checklist.append("- [ ] Business justification is clear and valid")
    checklist.append("- [ ] Key owner is appropriate and authorized")
    checklist.append("- [ ] Purpose aligns with business requirements")
    
    # Operational checks
    operational = data.get('operational', {})
    if operational:
        if operational.get('cost_center'):
            checklist.append("- [ ] Cost center is valid and approved for key management expenses")
        
        if operational.get('project_code'):
            checklist.append("- [ ] Project code is active and authorized")
    
    checklist.append("\n**Security Review:**")
    
    # Compliance checks
    compliance = data.get('compliance', {})
    pci_scope = compliance.get('pci_scope', 'none')
    nist_class = compliance.get('nist_classification', 'internal')
    
    checklist.append(f"- [ ] PCI scope ({pci_scope}) is correctly classified")
    checklist.append(f"- [ ] NIST classification ({nist_class}) is appropriate")
    
    if compliance.get('sox_applicable'):
        checklist.append("- [ ] SOX requirements are understood and will be met")
    
    if compliance.get('gdpr_applicable'):
        checklist.append("- [ ] GDPR requirements are understood and will be met")
        if compliance.get('retention_period_days'):
            checklist.append(f"- [ ] Data retention period ({compliance['retention_period_days']} days) is compliant")
    
    # Rotation policy
    rotation_days = data.get('rotation_interval_days', 0)
    checklist.append(f"- [ ] Rotation interval ({rotation_days} days) is appropriate for the risk level")
    
    # Risk assessment
    metadata = data.get('metadata', {})
    risk_level = metadata.get('risk_assessment', 'medium')
    checklist.append(f"- [ ] Risk assessment ({risk_level}) is accurate")
    
    # Environment-specific checks
    if environment.lower() in ['prod', 'production']:
        checklist.append("- [ ] **PRODUCTION KEY:** Extra scrutiny applied")
        checklist.append("- [ ] Non-production alternative considered and rejected")
        checklist.append("- [ ] Production deployment process documented")
    
    # High-risk checks
    if risk_level in ['high', 'critical'] or nist_class in ['secret', 'top-secret']:
        checklist.append("\n**High-Risk Key Additional Checks:**")
        checklist.append("- [ ] Security team has reviewed and approved")
        checklist.append("- [ ] Additional monitoring and alerting configured")
        checklist.append("- [ ] Incident response plan includes this key")
        checklist.append("- [ ] Key escrow/recovery procedures documented")
    
    # Relationships and dependencies
    relationships = data.get('relationships', {})
    if relationships:
        if relationships.get('depends_on'):
            checklist.append("- [ ] All dependency keys exist and are accessible")
        
        if relationships.get('used_by'):
            services = relationships['used_by']
            checklist.append(f"- [ ] Services using this key ({', '.join(services)}) are documented")
    
    checklist.append("\n**Operational Review:**")
    checklist.append("- [ ] Monitoring and alerting requirements defined")
    checklist.append("- [ ] Key provisioning process tested in non-production")
    checklist.append("- [ ] Documentation is complete and accessible")
    checklist.append("- [ ] Emergency contact information is current")
    
    # Lifecycle management
    lifecycle = data.get('lifecycle', {})
    emergency_contact = lifecycle.get('emergency_contact')
    if emergency_contact:
        checklist.append(f"- [ ] Emergency contact ({emergency_contact}) is valid and responsive")
    
    checklist.append("\n**Final Approval:**")
    checklist.append("- [ ] All technical requirements validated")
    checklist.append("- [ ] Business approval obtained")
    checklist.append("- [ ] Security review completed")
    checklist.append("- [ ] Compliance requirements verified")
    checklist.append("- [ ] Key-inventory admin approval granted")
    
    # Approval signatures
    checklist.append("\n#### ✍️ Required Approvals\n")
    checklist.append("**Technical Reviewer:** _[GitHub username and date]_")
    checklist.append("**Business Approver:** _[GitHub username and date]_")
    checklist.append("**Security Reviewer:** _[GitHub username and date]_")
    checklist.append("**Key-Inventory Admin:** _[GitHub username and date]_\n")
    
    # Additional notes section
    checklist.append("#### 📝 Additional Notes\n")
    checklist.append("_[Add any additional notes, concerns, or requirements here]_\n")
    
    return "\n".join(checklist)


def generate_pr_checklist(files: List[str]) -> str:
    """Generate complete PR approval checklist."""
    checklist = []
    
    checklist.append("# 🔐 Key Creation Approval Checklist\n")
    checklist.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    checklist.append(f"**Files in this PR:** {len(files)}\n")
    
    # Overall PR checks
    checklist.append("## 📋 Overall PR Review\n")
    checklist.append("- [ ] All files follow the enhanced key schema v2.0")
    checklist.append("- [ ] No duplicate key IDs or aliases")
    checklist.append("- [ ] All validation checks pass")
    checklist.append("- [ ] Compliance requirements met")
    checklist.append("- [ ] Security scan completed without issues")
    checklist.append("- [ ] Documentation updated if needed\n")
    
    # Process each file
    for file_path in files:
        if not file_path.strip():
            continue
        
        filename = os.path.basename(file_path)
        data = load_key_file(file_path)
        
        if data:
            file_checklist = generate_checklist_for_key(data, filename)
            checklist.append(file_checklist)
            checklist.append("\n---\n")
    
    # Final approval section
    checklist.append("## 🏁 Final Approval\n")
    checklist.append("- [ ] All individual key checklists completed")
    checklist.append("- [ ] Required approvals obtained")
    checklist.append("- [ ] Ready for merge and provisioning\n")
    
    checklist.append("**Approved by Key-Inventory Admin:** _[GitHub username and date]_\n")
    
    # Post-merge actions
    checklist.append("## 🚀 Post-Merge Actions\n")
    checklist.append("- [ ] Keys provisioned successfully")
    checklist.append("- [ ] Monitoring configured")
    checklist.append("- [ ] Documentation updated")
    checklist.append("- [ ] Key owners notified")
    checklist.append("- [ ] Compliance records updated\n")
    
    return "\n".join(checklist)


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: generate-approval-checklist.py <file1> [file2] ...")
        sys.exit(1)
    
    files_to_process = [f for f in sys.argv[1:] if f.strip()]
    
    if not files_to_process:
        print("No files to process")
        sys.exit(0)
    
    print(f"Generating approval checklist for {len(files_to_process)} files...")
    
    # Generate the complete checklist
    checklist = generate_pr_checklist(files_to_process)
    
    # Write to file for GitHub Actions
    with open('approval-checklist.md', 'w') as f:
        f.write(checklist)
    
    print("✅ Approval checklist generated successfully!")
    print("Check 'approval-checklist.md' for the complete checklist.")


if __name__ == "__main__":
    main()