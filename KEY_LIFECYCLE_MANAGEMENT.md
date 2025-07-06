# Key Lifecycle Management System

## Table of Contents
- [System Overview](#system-overview)
- [Architecture](#architecture)
- [Key Lifecycle Operations](#key-lifecycle-operations)
- [YAML Schema](#yaml-schema)
- [GitHub Actions Workflows](#github-actions-workflows)
- [RBAC and Approval Matrix](#rbac-and-approval-matrix)
- [Audit and Compliance](#audit-and-compliance)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Emergency Procedures](#emergency-procedures)
- [AI Agent Integration](#ai-agent-integration)
- [Setup Instructions](#setup-instructions)
- [Best Practices](#best-practices)

## System Overview

This is a comprehensive GitOps-based key lifecycle management system designed to handle the complete lifecycle of cryptographic keys, API keys, and secrets from creation to deletion. The system leverages GitHub as the central platform for version control, approvals, automation, and documentation.

### Key Principles
- **Everything as Code**: All operations are defined as code for AI agent compatibility
- **GitOps Workflow**: Git serves as the single source of truth
- **Immutable Audit Trail**: All changes are tracked and auditable
- **Principle of Least Privilege**: Role-based access control
- **Automated Compliance**: Built-in compliance checks and reporting

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              GitHub Repository                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐           │
│  │   inventory/    │    │   .github/      │    │     docs/       │           │
│  │  ├─ key1.yaml   │    │  └─ workflows/  │    │  ├─ index.html  │           │
│  │  ├─ key2.yaml   │    │     ├─ create   │    │  ├─ keys.json   │           │
│  │  └─ key3.yaml   │    │     ├─ delete   │    │  └─ audit.html  │           │
│  └─────────────────┘    │     ├─ rotate   │    └─────────────────┘           │
│                         │     └─ emergency│                                   │
│                         └─────────────────┘                                   │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                              GitHub Actions                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐           │
│  │   Validation    │    │   Notification  │    │    Monitoring   │           │
│  │  ├─ Schema      │    │  ├─ Slack/Teams │    │  ├─ Rotation    │           │
│  │  ├─ Compliance  │    │  ├─ Email       │    │  ├─ Expiration  │           │
│  │  └─ Duplicates  │    │  └─ GitHub      │    │  └─ Health      │           │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘           │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                              GitHub Pages                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐           │
│  │   Dashboard     │    │   Audit Trail   │    │   Compliance    │           │
│  │  ├─ Search      │    │  ├─ Changes     │    │  ├─ PCI Reports │           │
│  │  ├─ Filter      │    │  ├─ Approvals   │    │  ├─ NIST Class  │           │
│  │  └─ Actions     │    │  └─ Timeline    │    │  └─ Rotation    │           │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          External Integrations                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐           │
│  │   Key Stores    │    │   Notification  │    │   Monitoring    │           │
│  │  ├─ AWS KMS     │    │  ├─ Slack       │    │  ├─ DataDog     │           │
│  │  ├─ HashiCorp   │    │  ├─ MS Teams    │    │  ├─ Prometheus  │           │
│  │  └─ Azure KV    │    │  └─ PagerDuty   │    │  └─ Grafana     │           │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘           │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Key Lifecycle Operations

### 1. Key Creation Workflow

**Process:**
1. Developer creates new YAML file in `inventory/` directory
2. Creates feature branch and submits PR
3. Automated validation runs (schema, duplicates, compliance)
4. Key-inventory admin reviews and approves
5. Automated provisioning in target key store
6. Documentation update and notification

**Actors:**
- **Developer**: Creates key request
- **Key-inventory Admin**: Reviews and approves
- **GitHub Actions**: Validates and provisions

### 2. Key Deletion Workflow

**Process:**
1. Team member initiates deletion via web interface
2. Automated branch creation with deletion request
3. PR created with deletion justification
4. Admin approval required
5. Automated key revocation in target store
6. Audit trail update and notification

**Actors:**
- **Team Member**: Initiates deletion
- **Key-inventory Admin**: Approves deletion
- **GitHub Actions**: Executes deletion

### 3. Key Rotation Workflow

**Process:**
1. Automated monitoring detects rotation due date
2. Notification sent to key owner
3. Grace period for manual rotation
4. Automated rotation if no manual action
5. New key provisioned, old key deprecated
6. Update inventory and notify stakeholders

**Actors:**
- **GitHub Actions**: Monitors and rotates
- **Key Owner**: Receives notifications
- **Key-inventory Admin**: Handles exceptions

### 4. Emergency Key Replacement

**Process:**
1. Emergency workflow triggered manually
2. Immediate key revocation in target store
3. New key provisioned with emergency metadata
4. Incident tracking and documentation
5. Post-incident review and compliance reporting

**Actors:**
- **Security Team**: Triggers emergency workflow
- **Key-inventory Admin**: Oversees process
- **GitHub Actions**: Executes emergency procedures

## YAML Schema

### Enhanced Key Schema v2.0

```yaml
# Required fields
key_id: string (UUID v4)
alias: string (alphanumeric, hyphens, underscores)
environment: string (dev|staging|prod)
owner: string (email)
purpose: string (description)
created_at: string (ISO 8601 datetime)
rotation_interval_days: integer (1-3650)
location: string (URI to key store)

# Compliance
compliance:
  pci_scope: string (none|cardholder-data|out-of-scope)
  nist_classification: string (internal|confidential|secret|top-secret)
  sox_applicable: boolean
  gdpr_applicable: boolean
  retention_period_days: integer

# Lifecycle metadata
lifecycle:
  status: string (active|deprecated|revoked|emergency-replaced)
  created_by: string (GitHub username)
  approved_by: string (GitHub username)
  approved_at: string (ISO 8601 datetime)
  last_rotated_at: string (ISO 8601 datetime)
  next_rotation_due: string (ISO 8601 datetime)
  rotation_count: integer
  emergency_contact: string (email)

# Technical details
technical:
  key_type: string (rsa|ec|symmetric|api-key|jwt)
  key_size: integer (optional)
  algorithm: string (optional)
  encoding: string (optional)
  key_store_type: string (aws-kms|azure-kv|hashicorp-vault|custom)
  high_availability: boolean
  backup_location: string (URI, optional)

# Dependencies and relationships
relationships:
  depends_on: array of strings (key_ids)
  used_by: array of strings (service names)
  related_keys: array of strings (key_ids)
  environments: array of strings (if key spans multiple envs)

# Operational
operational:
  monitoring_enabled: boolean
  alerting_enabled: boolean
  auto_rotation_enabled: boolean
  emergency_revocation_enabled: boolean
  cost_center: string
  project_code: string

# Audit and compliance
audit:
  access_logs_enabled: boolean
  usage_tracking_enabled: boolean
  compliance_scan_enabled: boolean
  last_compliance_check: string (ISO 8601 datetime)
  compliance_status: string (compliant|non-compliant|needs-review)

# Metadata
metadata:
  version: string (schema version)
  documentation_url: string (URL to additional docs)
  ticket_reference: string (Jira/GitHub issue)
  business_justification: string
  risk_assessment: string (low|medium|high|critical)

# Tags for categorization
tags: array of strings

# Optional custom fields
custom_fields: object (key-value pairs)
```

### Example Enhanced Key Definition

```yaml
# inventory/a1b2c3d4-e5f6-7890-1234-567890abcdef.yaml
key_id: a1b2c3d4-e5f6-7890-1234-567890abcdef
alias: payment-service-jwt-prod
environment: prod
owner: payments-team@company.com
purpose: JWT signing for payment service authentication
created_at: "2024-01-20T14:30:00Z"
rotation_interval_days: 90
location: "aws-kms://arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-7890-1234-567890abcdef"

compliance:
  pci_scope: cardholder-data
  nist_classification: confidential
  sox_applicable: true
  gdpr_applicable: true
  retention_period_days: 2555

lifecycle:
  status: active
  created_by: john.doe
  approved_by: jane.admin
  approved_at: "2024-01-20T15:00:00Z"
  last_rotated_at: "2024-01-20T14:30:00Z"
  next_rotation_due: "2024-04-20T14:30:00Z"
  rotation_count: 0
  emergency_contact: security-team@company.com

technical:
  key_type: rsa
  key_size: 2048
  algorithm: RS256
  encoding: pkcs8
  key_store_type: aws-kms
  high_availability: true
  backup_location: "aws-kms://arn:aws:kms:us-west-2:123456789012:key/backup-key-id"

relationships:
  depends_on: []
  used_by: ["payment-service", "fraud-detection-service"]
  related_keys: ["b2c3d4e5-f6a7-8901-2345-678901bcdef0"]
  environments: ["prod"]

operational:
  monitoring_enabled: true
  alerting_enabled: true
  auto_rotation_enabled: true
  emergency_revocation_enabled: true
  cost_center: "CC-PAYMENTS-001"
  project_code: "PROJ-PAY-2024"

audit:
  access_logs_enabled: true
  usage_tracking_enabled: true
  compliance_scan_enabled: true
  last_compliance_check: "2024-01-20T14:30:00Z"
  compliance_status: compliant

metadata:
  version: "2.0"
  documentation_url: "https://wiki.company.com/payments/keys/jwt-signing"
  ticket_reference: "JIRA-12345"
  business_justification: "Required for PCI-compliant payment processing"
  risk_assessment: high

tags: [jwt, payments, pci, production, high-risk]

custom_fields:
  business_owner: "payments-product-owner@company.com"
  disaster_recovery_tier: "tier-1"
  encryption_at_rest: true
```

## GitHub Actions Workflows

### 1. Key Creation Workflow

```yaml
# .github/workflows/key-creation.yml
name: Key Creation Workflow

on:
  pull_request:
    paths:
      - 'inventory/*.yaml'
      - 'inventory/*.yml'
    types: [opened, synchronize, reopened]

jobs:
  validate-key-creation:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install pyyaml jsonschema requests
      
      - name: Detect changed files
        id: changed-files
        uses: tj-actions/changed-files@v40
        with:
          files: |
            inventory/*.yaml
            inventory/*.yml
      
      - name: Validate new keys
        run: |
          python scripts/validate-key-creation.py ${{ steps.changed-files.outputs.all_changed_files }}
      
      - name: Check for duplicates
        run: |
          python scripts/check-duplicates.py ${{ steps.changed-files.outputs.all_changed_files }}
      
      - name: Compliance check
        run: |
          python scripts/compliance-check.py ${{ steps.changed-files.outputs.all_changed_files }}
      
      - name: Add PR comment
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            let comment = '## ❌ Key Creation Validation Failed\n\n';
            
            if (fs.existsSync('validation-errors.txt')) {
              comment += '### Validation Errors:\n';
              comment += fs.readFileSync('validation-errors.txt', 'utf8');
            }
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
      
      - name: Security scan
        run: |
          python scripts/security-scan.py ${{ steps.changed-files.outputs.all_changed_files }}
      
      - name: Generate approval checklist
        run: |
          python scripts/generate-approval-checklist.py ${{ steps.changed-files.outputs.all_changed_files }}
      
      - name: Update PR with checklist
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('approval-checklist.md')) {
              const checklist = fs.readFileSync('approval-checklist.md', 'utf8');
              
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: checklist
              });
            }

  provision-key:
    runs-on: ubuntu-latest
    needs: validate-key-creation
    if: github.event.pull_request.merged == true
    environment: key-provisioning
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup cloud credentials
        run: |
          echo "Setting up AWS/Azure/GCP credentials"
          # Configure credentials based on key store type
      
      - name: Provision key in target store
        run: |
          python scripts/provision-key.py ${{ github.event.pull_request.merged_at }}
      
      - name: Update key metadata
        run: |
          python scripts/update-key-metadata.py --status=provisioned
      
      - name: Send notification
        run: |
          python scripts/send-notification.py --type=key-created
      
      - name: Update documentation
        run: |
          python build-data.py --include-metadata
          git add docs/keys.json
          git commit -m "docs: update key inventory after provisioning"
          git push
```

### 2. Key Deletion Workflow

```yaml
# .github/workflows/key-deletion.yml
name: Key Deletion Workflow

on:
  pull_request:
    paths:
      - 'inventory/*.yaml'
      - 'inventory/*.yml'
    types: [opened, synchronize, reopened]
  
  workflow_dispatch:
    inputs:
      key_id:
        description: 'Key ID to delete'
        required: true
        type: string
      reason:
        description: 'Reason for deletion'
        required: true
        type: string
      emergency:
        description: 'Emergency deletion'
        required: false
        type: boolean
        default: false

jobs:
  validate-deletion:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Detect deleted files
        id: deleted-files
        uses: tj-actions/changed-files@v40
        with:
          files: |
            inventory/*.yaml
            inventory/*.yml
          files_deleted: true
      
      - name: Validate deletion request
        run: |
          python scripts/validate-deletion.py ${{ steps.deleted-files.outputs.deleted_files }}
      
      - name: Check dependencies
        run: |
          python scripts/check-key-dependencies.py ${{ steps.deleted-files.outputs.deleted_files }}
      
      - name: Compliance check for deletion
        run: |
          python scripts/compliance-deletion-check.py ${{ steps.deleted-files.outputs.deleted_files }}
      
      - name: Generate deletion impact report
        run: |
          python scripts/deletion-impact-report.py ${{ steps.deleted-files.outputs.deleted_files }}
      
      - name: Add deletion report to PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('deletion-report.md')) {
              const report = fs.readFileSync('deletion-report.md', 'utf8');
              
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: report
              });
            }

  execute-deletion:
    runs-on: ubuntu-latest
    needs: validate-deletion
    if: github.event.pull_request.merged == true || github.event_name == 'workflow_dispatch'
    environment: key-deletion
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup cloud credentials
        run: |
          echo "Setting up credentials for key store access"
      
      - name: Revoke key in target store
        run: |
          python scripts/revoke-key.py ${{ inputs.key_id || github.event.pull_request.number }}
      
      - name: Update audit trail
        run: |
          python scripts/update-audit-trail.py --action=deleted --key-id=${{ inputs.key_id }}
      
      - name: Send deletion notification
        run: |
          python scripts/send-notification.py --type=key-deleted --key-id=${{ inputs.key_id }}
      
      - name: Emergency procedures
        if: ${{ inputs.emergency == true }}
        run: |
          python scripts/emergency-procedures.py --key-id=${{ inputs.key_id }}
```

### 3. Key Rotation Workflow

```yaml
# .github/workflows/key-rotation.yml
name: Key Rotation Workflow

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  
  workflow_dispatch:
    inputs:
      key_id:
        description: 'Key ID to rotate'
        required: true
        type: string
      force:
        description: 'Force rotation'
        required: false
        type: boolean
        default: false

jobs:
  check-rotation-due:
    runs-on: ubuntu-latest
    outputs:
      keys-to-rotate: ${{ steps.check-rotation.outputs.keys }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Check rotation due dates
        id: check-rotation
        run: |
          python scripts/check-rotation-due.py --output-json
      
      - name: Send rotation warnings
        run: |
          python scripts/send-rotation-warnings.py

  rotate-keys:
    runs-on: ubuntu-latest
    needs: check-rotation-due
    if: needs.check-rotation-due.outputs.keys-to-rotate != '[]'
    environment: key-rotation
    strategy:
      matrix:
        key: ${{ fromJson(needs.check-rotation-due.outputs.keys-to-rotate) }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup cloud credentials
        run: |
          echo "Setting up credentials for key rotation"
      
      - name: Rotate key
        run: |
          python scripts/rotate-key.py --key-id=${{ matrix.key.key_id }}
      
      - name: Update key metadata
        run: |
          python scripts/update-key-after-rotation.py --key-id=${{ matrix.key.key_id }}
      
      - name: Verify rotation
        run: |
          python scripts/verify-key-rotation.py --key-id=${{ matrix.key.key_id }}
      
      - name: Update inventory
        run: |
          git add inventory/${{ matrix.key.key_id }}.yaml
          git commit -m "feat: rotate key ${{ matrix.key.alias }} (${{ matrix.key.key_id }})"
          git push
      
      - name: Send rotation notification
        run: |
          python scripts/send-notification.py --type=key-rotated --key-id=${{ matrix.key.key_id }}
```

### 4. Emergency Key Replacement Workflow

```yaml
# .github/workflows/emergency-key-replacement.yml
name: Emergency Key Replacement

on:
  workflow_dispatch:
    inputs:
      key_id:
        description: 'Key ID to replace'
        required: true
        type: string
      incident_id:
        description: 'Incident ID'
        required: true
        type: string
      reason:
        description: 'Reason for emergency replacement'
        required: true
        type: string
      severity:
        description: 'Incident severity'
        required: true
        type: choice
        options:
          - low
          - medium
          - high
          - critical
      immediate_revocation:
        description: 'Immediately revoke old key'
        required: false
        type: boolean
        default: true

jobs:
  emergency-replacement:
    runs-on: ubuntu-latest
    environment: emergency-key-ops
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Validate emergency request
        run: |
          python scripts/validate-emergency-request.py --key-id=${{ inputs.key_id }}
      
      - name: Setup cloud credentials
        run: |
          echo "Setting up emergency credentials"
      
      - name: Immediate revocation
        if: ${{ inputs.immediate_revocation == true }}
        run: |
          python scripts/emergency-revoke-key.py --key-id=${{ inputs.key_id }}
      
      - name: Generate replacement key
        run: |
          python scripts/generate-replacement-key.py --key-id=${{ inputs.key_id }} --incident-id=${{ inputs.incident_id }}
      
      - name: Update key inventory
        run: |
          python scripts/update-emergency-replacement.py --key-id=${{ inputs.key_id }}
      
      - name: Create incident tracking
        run: |
          python scripts/create-incident-tracking.py --incident-id=${{ inputs.incident_id }}
      
      - name: Send emergency notifications
        run: |
          python scripts/send-emergency-notifications.py --key-id=${{ inputs.key_id }} --severity=${{ inputs.severity }}
      
      - name: Update compliance records
        run: |
          python scripts/update-compliance-emergency.py --key-id=${{ inputs.key_id }}
      
      - name: Generate incident report
        run: |
          python scripts/generate-incident-report.py --incident-id=${{ inputs.incident_id }}
      
      - name: Create follow-up issues
        uses: actions/github-script@v6
        with:
          script: |
            const issue = await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `Emergency Key Replacement Follow-up: ${{ inputs.key_id }}`,
              body: `
                ## Emergency Key Replacement Follow-up
                
                **Incident ID:** ${{ inputs.incident_id }}
                **Key ID:** ${{ inputs.key_id }}
                **Severity:** ${{ inputs.severity }}
                **Reason:** ${{ inputs.reason }}
                
                ### Follow-up Actions Required:
                - [ ] Review incident response
                - [ ] Update documentation
                - [ ] Conduct post-incident review
                - [ ] Update emergency procedures if needed
                - [ ] Compliance reporting
              `,
              labels: ['emergency', 'key-management', 'follow-up']
            });
```

## RBAC and Approval Matrix

### Repository Permissions

```yaml
# .github/CODEOWNERS
# Key inventory administrators
/inventory/ @key-inventory-admins

# Workflows and automation
/.github/workflows/ @key-inventory-admins @security-team

# Documentation and reports
/docs/ @key-inventory-admins @security-team

# Emergency procedures
/.github/workflows/emergency-key-replacement.yml @security-team
```

### Branch Protection Rules

```yaml
# Branch protection configuration
branch_protection:
  main:
    required_status_checks:
      - validate-key-creation
      - security-scan
      - compliance-check
    required_reviewers: 2
    required_reviewer_teams:
      - key-inventory-admins
    dismiss_stale_reviews: true
    require_code_owner_reviews: true
    restrictions:
      push: []
      merge: [key-inventory-admins]
    enforce_admins: true
    required_linear_history: true
    allow_force_pushes: false
    allow_deletions: false
```

### Role Definitions

#### Key Inventory Admins
**Responsibilities:**
- Approve/reject key creation requests
- Approve/reject key deletion requests
- Manage emergency key replacements
- Oversee compliance and audit processes
- Manage workflow configurations

**Permissions:**
- Write access to repository
- Approve pull requests
- Trigger manual workflows
- Access to production key stores
- Admin access to GitHub repository

#### Security Team
**Responsibilities:**
- Trigger emergency procedures
- Review security incidents
- Manage compliance reporting
- Conduct security audits
- Respond to security alerts

**Permissions:**
- Trigger emergency workflows
- Access to audit logs
- Read/write to security documentation
- Access to monitoring dashboards
- Incident response workflows

#### Developers
**Responsibilities:**
- Submit key creation requests
- Follow key lifecycle procedures
- Maintain key documentation
- Report security issues

**Permissions:**
- Create branches and pull requests
- Read access to inventory
- Access to documentation
- Submit issues and discussions

#### Key Owners
**Responsibilities:**
- Manage assigned keys
- Respond to rotation notifications
- Maintain key usage documentation
- Report key lifecycle changes

**Permissions:**
- Update keys they own
- Request key rotations
- Access to key monitoring
- Receive notifications

### Approval Matrix

| Operation | Developer | Key Owner | Security Team | Key-Inventory Admin |
|-----------|-----------|-----------|---------------|-------------------|
| Create Key | Request | N/A | Review | **Approve** |
| Delete Key | Request | Request | Review | **Approve** |
| Rotate Key | Request | Request | Review | **Approve** |
| Emergency Replace | N/A | Request | **Approve** | **Approve** |
| Modify Workflow | N/A | N/A | **Approve** | **Approve** |
| Access Audit Logs | N/A | Limited | **Full** | **Full** |
| Configure Monitoring | N/A | N/A | **Configure** | **Configure** |

## Audit and Compliance

### Audit Trail Components

1. **Git History**: Complete version control of all changes
2. **GitHub Actions Logs**: Detailed workflow execution logs
3. **Key Store Audit Logs**: Native audit logs from key stores
4. **Compliance Reports**: Regular compliance status reports
5. **Access Logs**: Who accessed what and when
6. **Notification Logs**: All notifications sent and received

### Compliance Tracking

```yaml
# scripts/compliance-tracker.yml
compliance_frameworks:
  pci_dss:
    requirements:
      - data_encryption
      - access_controls
      - audit_logging
      - key_management
    monitoring:
      - automatic_scans
      - quarterly_reviews
      - annual_assessments
  
  sox:
    requirements:
      - segregation_of_duties
      - audit_trails
      - access_controls
      - change_management
    monitoring:
      - continuous_monitoring
      - management_reviews
      - external_audits
  
  gdpr:
    requirements:
      - data_protection
      - access_rights
      - breach_notification
      - privacy_by_design
    monitoring:
      - privacy_impact_assessments
      - data_protection_reviews
      - incident_response
  
  nist:
    requirements:
      - identification
      - protection
      - detection
      - response
      - recovery
    monitoring:
      - security_controls
      - risk_assessments
      - continuous_monitoring
```

### Automated Compliance Reporting

```python
# scripts/generate-compliance-report.py
#!/usr/bin/env python3
"""
Generate comprehensive compliance reports
"""

import json
import yaml
from datetime import datetime, timedelta
from pathlib import Path

def generate_compliance_report():
    """Generate compliance report for all frameworks"""
    
    # Load all keys
    keys = load_all_keys()
    
    # Generate PCI DSS Report
    pci_report = generate_pci_report(keys)
    
    # Generate SOX Report
    sox_report = generate_sox_report(keys)
    
    # Generate GDPR Report
    gdpr_report = generate_gdpr_report(keys)
    
    # Generate NIST Report
    nist_report = generate_nist_report(keys)
    
    # Combined report
    compliance_report = {
        "generated_at": datetime.now().isoformat(),
        "reporting_period": {
            "start": (datetime.now() - timedelta(days=30)).isoformat(),
            "end": datetime.now().isoformat()
        },
        "frameworks": {
            "pci_dss": pci_report,
            "sox": sox_report,
            "gdpr": gdpr_report,
            "nist": nist_report
        },
        "summary": generate_compliance_summary(keys)
    }
    
    # Save report
    with open('docs/compliance-report.json', 'w') as f:
        json.dump(compliance_report, f, indent=2)
    
    # Generate HTML report
    generate_html_compliance_report(compliance_report)

def generate_pci_report(keys):
    """Generate PCI DSS compliance report"""
    pci_keys = [k for k in keys if k.get('compliance', {}).get('pci_scope') != 'none']
    
    return {
        "total_keys": len(pci_keys),
        "compliant_keys": len([k for k in pci_keys if is_pci_compliant(k)]),
        "non_compliant_keys": len([k for k in pci_keys if not is_pci_compliant(k)]),
        "key_rotation_compliance": check_rotation_compliance(pci_keys),
        "access_control_compliance": check_access_control_compliance(pci_keys),
        "audit_logging_compliance": check_audit_logging_compliance(pci_keys)
    }

if __name__ == "__main__":
    generate_compliance_report()
```

## Monitoring and Alerting

### Monitoring Dashboard

```yaml
# monitoring/dashboard-config.yml
dashboard:
  name: "Key Inventory Management"
  refresh_interval: "30s"
  
  panels:
    - title: "Key Inventory Overview"
      type: "stat"
      metrics:
        - total_keys
        - active_keys
        - deprecated_keys
        - revoked_keys
    
    - title: "Rotation Status"
      type: "graph"
      metrics:
        - keys_due_for_rotation
        - keys_overdue_for_rotation
        - successful_rotations
        - failed_rotations
    
    - title: "Compliance Status"
      type: "pie"
      metrics:
        - pci_compliant_keys
        - sox_compliant_keys
        - gdpr_compliant_keys
        - nist_compliant_keys
    
    - title: "Environment Distribution"
      type: "donut"
      metrics:
        - prod_keys
        - staging_keys
        - dev_keys
    
    - title: "Security Events"
      type: "table"
      metrics:
        - emergency_replacements
        - unauthorized_access_attempts
        - compliance_violations
        - audit_failures
    
    - title: "Key Store Health"
      type: "status"
      metrics:
        - aws_kms_health
        - azure_kv_health
        - hashicorp_vault_health
        - custom_store_health

alerts:
  - name: "Key Rotation Overdue"
    condition: "keys_overdue_for_rotation > 0"
    severity: "warning"
    channels: ["slack", "email"]
    
  - name: "Compliance Violation"
    condition: "compliance_violations > 0"
    severity: "critical"
    channels: ["slack", "email", "pagerduty"]
    
  - name: "Emergency Key Replacement"
    condition: "emergency_replacements > 0"
    severity: "critical"
    channels: ["slack", "email", "pagerduty", "sms"]
    
  - name: "Key Store Down"
    condition: "key_store_health < 100"
    severity: "critical"
    channels: ["slack", "email", "pagerduty"]
    
  - name: "Unauthorized Access"
    condition: "unauthorized_access_attempts > 0"
    severity: "high"
    channels: ["slack", "email", "security-team"]
```

### Alert Notification System

```python
# scripts/alert-manager.py
#!/usr/bin/env python3
"""
Alert notification system for key inventory management
"""

import json
import requests
from datetime import datetime
from typing import Dict, List, Any

class AlertManager:
    def __init__(self):
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
        self.email_config = self.load_email_config()
        self.pagerduty_config = self.load_pagerduty_config()
    
    def send_alert(self, alert_type: str, severity: str, message: str, data: Dict[str, Any]):
        """Send alert to appropriate channels based on severity"""
        
        alert_config = self.get_alert_config(alert_type, severity)
        
        for channel in alert_config.get('channels', []):
            if channel == 'slack':
                self.send_slack_alert(alert_type, severity, message, data)
            elif channel == 'email':
                self.send_email_alert(alert_type, severity, message, data)
            elif channel == 'pagerduty':
                self.send_pagerduty_alert(alert_type, severity, message, data)
            elif channel == 'sms':
                self.send_sms_alert(alert_type, severity, message, data)
    
    def send_slack_alert(self, alert_type: str, severity: str, message: str, data: Dict[str, Any]):
        """Send Slack notification"""
        
        color_map = {
            'low': '#36a64f',
            'warning': '#ff9900',
            'high': '#ff6600',
            'critical': '#ff0000'
        }
        
        payload = {
            "text": f"🔐 Key Inventory Alert: {alert_type}",
            "attachments": [
                {
                    "color": color_map.get(severity, '#ff0000'),
                    "fields": [
                        {
                            "title": "Severity",
                            "value": severity.upper(),
                            "short": True
                        },
                        {
                            "title": "Alert Type",
                            "value": alert_type,
                            "short": True
                        },
                        {
                            "title": "Message",
                            "value": message,
                            "short": False
                        },
                        {
                            "title": "Timestamp",
                            "value": datetime.now().isoformat(),
                            "short": True
                        }
                    ]
                }
            ]
        }
        
        if data:
            payload["attachments"][0]["fields"].append({
                "title": "Additional Data",
                "value": json.dumps(data, indent=2),
                "short": False
            })
        
        response = requests.post(self.slack_webhook, json=payload)
        response.raise_for_status()
    
    def send_email_alert(self, alert_type: str, severity: str, message: str, data: Dict[str, Any]):
        """Send email notification"""
        # Implementation for email alerts
        pass
    
    def send_pagerduty_alert(self, alert_type: str, severity: str, message: str, data: Dict[str, Any]):
        """Send PagerDuty notification"""
        # Implementation for PagerDuty alerts
        pass
    
    def send_sms_alert(self, alert_type: str, severity: str, message: str, data: Dict[str, Any]):
        """Send SMS notification"""
        # Implementation for SMS alerts
        pass

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: alert-manager.py <alert_type> <severity> <message>")
        sys.exit(1)
    
    alert_manager = AlertManager()
    alert_manager.send_alert(sys.argv[1], sys.argv[2], sys.argv[3], {})
```

## Emergency Procedures

### Emergency Response Playbook

#### 1. Key Compromise Response

**Detection:**
- Security monitoring alerts
- Unusual access patterns
- Security team notification
- Automated threat detection

**Response Steps:**
1. **Immediate Assessment** (0-15 minutes)
   - Validate the compromise
   - Determine impact scope
   - Identify affected systems
   - Assemble response team

2. **Containment** (15-30 minutes)
   - Trigger emergency key replacement workflow
   - Revoke compromised key immediately
   - Block unauthorized access
   - Isolate affected systems

3. **Recovery** (30-60 minutes)
   - Generate and deploy new keys
   - Verify system functionality
   - Update key inventory
   - Restore normal operations

4. **Communication** (Ongoing)
   - Notify stakeholders
   - Update incident tracking
   - Communicate with compliance teams
   - Document all actions

#### 2. Key Store Outage Response

**Detection:**
- Key store health monitoring
- Application error alerts
- Service degradation alerts
- Manual reports

**Response Steps:**
1. **Assessment** (0-10 minutes)
   - Verify outage scope
   - Check backup systems
   - Identify affected applications
   - Activate backup procedures

2. **Failover** (10-30 minutes)
   - Switch to backup key store
   - Verify failover success
   - Test critical applications
   - Monitor system health

3. **Communication** (Ongoing)
   - Notify affected teams
   - Update status page
   - Provide ETA for resolution
   - Document incident

### Emergency Contacts

```yaml
# emergency-contacts.yml
emergency_contacts:
  primary:
    security_team:
      email: security-team@company.com
      slack: "#security-alerts"
      pagerduty: "security-team-escalation"
      phone: "+1-555-SECURITY"
    
    key_inventory_admins:
      email: key-admins@company.com
      slack: "#key-inventory-admins"
      pagerduty: "key-admin-escalation"
      phone: "+1-555-KEY-ADMIN"
  
  secondary:
    infrastructure_team:
      email: infra-team@company.com
      slack: "#infrastructure"
      pagerduty: "infra-escalation"
    
    compliance_team:
      email: compliance@company.com
      slack: "#compliance"
      pagerduty: "compliance-escalation"
  
  vendors:
    aws_support:
      phone: "+1-206-266-4064"
      case_url: "https://console.aws.amazon.com/support/"
    
    azure_support:
      phone: "+1-800-642-7676"
      case_url: "https://portal.azure.com/#blade/Microsoft_Azure_Support/HelpAndSupportBlade"
```

## AI Agent Integration

### Context Files for AI Agents

```yaml
# .ai-context/key-inventory-context.yml
system_description: |
  This is a GitOps-based key lifecycle management system for cryptographic keys, 
  API keys, and secrets. The system uses GitHub as the central platform for 
  version control, approvals, automation, and documentation.

key_concepts:
  - GitOps workflow with GitHub as single source of truth
  - YAML-based key inventory in inventory/ directory
  - Automated workflows for key lifecycle operations
  - Role-based access control and approval processes
  - Comprehensive audit trail and compliance tracking

file_structure:
  inventory/: "YAML files defining cryptographic keys (one per key)"
  .github/workflows/: "GitHub Actions workflows for automation"
  docs/: "Generated documentation and web interface"
  scripts/: "Python scripts for key management operations"
  monitoring/: "Monitoring and alerting configurations"

common_operations:
  create_key: "Create new YAML file in inventory/, submit PR for approval"
  delete_key: "Remove YAML file from inventory/, submit PR for approval"
  rotate_key: "Automated rotation based on rotation_interval_days"
  emergency_replace: "Manual workflow for compromised keys"

workflows:
  key_creation: ".github/workflows/key-creation.yml"
  key_deletion: ".github/workflows/key-deletion.yml"
  key_rotation: ".github/workflows/key-rotation.yml"
  emergency_replacement: ".github/workflows/emergency-key-replacement.yml"

validation_rules:
  required_fields: [key_id, alias, environment, owner, purpose, created_at, rotation_interval_days, location, compliance, tags]
  key_id_format: "UUID v4"
  environment_values: [dev, staging, prod]
  compliance_pci_scope: [none, cardholder-data, out-of-scope]
  compliance_nist_classification: [internal, confidential, secret, top-secret]

approval_matrix:
  key_creation: "Requires key-inventory-admin approval"
  key_deletion: "Requires key-inventory-admin approval"
  emergency_operations: "Requires security-team approval"
  workflow_changes: "Requires security-team and key-inventory-admin approval"
```

### AI Agent Usage Examples

```python
# Example AI agent interaction
agent_instructions = """
You are a key inventory management assistant. You have access to a GitOps-based 
key lifecycle management system with the following capabilities:

1. Create new cryptographic keys by generating YAML files
2. Delete existing keys through PR-based workflow
3. Rotate keys based on expiration dates
4. Handle emergency key replacements
5. Generate compliance reports
6. Monitor key health and usage

When users request key operations:
- Always validate input against the schema
- Follow the approval workflow requirements
- Generate appropriate GitHub Actions workflows
- Ensure compliance with security policies
- Document all changes in the audit trail

Use the context files in .ai-context/ to understand system structure and operations.
"""

# Example usage:
# AI Agent: "I need to create a new JWT signing key for the payment service"
# System: Creates YAML file, validates schema, generates PR, triggers approval workflow
```

## Setup Instructions

### 1. Repository Setup

```bash
# Clone the repository
git clone https://github.com/your-org/key-inventory.git
cd key-inventory

# Create required directories
mkdir -p inventory
mkdir -p .github/workflows
mkdir -p scripts
mkdir -p docs
mkdir -p monitoring
mkdir -p .ai-context

# Set up Python environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Initialize the inventory
python build-data.py --include-metadata
```

### 2. GitHub Repository Configuration

```bash
# Set up branch protection
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["validate-key-creation","security-scan","compliance-check"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":2,"dismiss_stale_reviews":true,"require_code_owner_reviews":true}' \
  --field restrictions='{"users":[],"teams":["key-inventory-admins"]}'

# Set up environments
gh api repos/:owner/:repo/environments/key-provisioning --method PUT
gh api repos/:owner/:repo/environments/key-deletion --method PUT
gh api repos/:owner/:repo/environments/key-rotation --method PUT
gh api repos/:owner/:repo/environments/emergency-key-ops --method PUT
```

### 3. Team and Permission Setup

```bash
# Create teams
gh api orgs/:org/teams --method POST --field name="key-inventory-admins"
gh api orgs/:org/teams --method POST --field name="security-team"

# Add team members
gh api orgs/:org/teams/key-inventory-admins/memberships/:username --method PUT
gh api orgs/:org/teams/security-team/memberships/:username --method PUT

# Set repository permissions
gh api repos/:owner/:repo/collaborators/key-inventory-admins --method PUT --field permission="admin"
gh api repos/:owner/:repo/collaborators/security-team --method PUT --field permission="write"
```

### 4. External Service Integration

```bash
# AWS KMS integration
aws configure set region us-east-1
aws iam create-role --role-name KeyInventoryRole --assume-role-policy-document file://aws-trust-policy.json
aws iam attach-role-policy --role-name KeyInventoryRole --policy-arn arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser

# Azure Key Vault integration
az login
az ad sp create-for-rbac --name "KeyInventoryApp" --role "Key Vault Administrator"

# HashiCorp Vault integration
vault auth enable github
vault write auth/github/config organization=your-org
vault write auth/github/map/teams/key-inventory-admins value=key-admin-policy
```

### 5. Monitoring Setup

```bash
# Set up monitoring dashboards
# Configure Grafana/DataDog/Prometheus based on your monitoring stack

# Set up alerting
# Configure Slack/PagerDuty/email notifications

# Test monitoring
python scripts/test-monitoring.py
```

## Best Practices

### 1. Security Best Practices

- **Principle of Least Privilege**: Grant minimum required permissions
- **Separation of Duties**: Separate key creation, approval, and provisioning
- **Regular Audits**: Conduct quarterly access reviews and compliance audits
- **Secure Key Storage**: Use hardware security modules (HSMs) for critical keys
- **Backup and Recovery**: Maintain secure backups of key metadata and policies

### 2. Operational Best Practices

- **Automation First**: Automate all routine operations
- **Documentation**: Maintain up-to-date documentation for all processes
- **Testing**: Regularly test emergency procedures and recovery processes
- **Monitoring**: Implement comprehensive monitoring and alerting
- **Training**: Provide regular training for all team members

### 3. Compliance Best Practices

- **Regular Assessments**: Conduct regular compliance assessments
- **Audit Trail**: Maintain comprehensive audit trails for all operations
- **Policy Updates**: Keep policies updated with regulatory changes
- **Incident Response**: Maintain and test incident response procedures
- **Vendor Management**: Ensure third-party vendors meet compliance requirements

### 4. Development Best Practices

- **Code Reviews**: Require code reviews for all changes
- **Testing**: Implement comprehensive testing for all automation
- **Version Control**: Use semantic versioning for all components
- **Documentation**: Document all APIs and interfaces
- **Error Handling**: Implement robust error handling and logging

### 5. Key Management Best Practices

- **Rotation Policies**: Implement appropriate rotation policies based on risk
- **Access Controls**: Implement strong access controls and authentication
- **Encryption**: Encrypt keys at rest and in transit
- **Key Escrow**: Implement key escrow for business continuity
- **Lifecycle Management**: Properly manage keys throughout their lifecycle

---

## Conclusion

This comprehensive key lifecycle management system provides a robust, scalable, and compliant solution for managing cryptographic keys in a GitOps environment. The system leverages GitHub's native features for version control, approvals, and automation while providing comprehensive audit trails and compliance reporting.

The architecture is designed to be AI-agent friendly, with clear documentation, structured workflows, and comprehensive context files that enable AI agents to understand and operate within the system effectively.

For questions or support, please refer to the documentation or contact the key inventory administrators through the appropriate channels defined in the emergency contacts section.