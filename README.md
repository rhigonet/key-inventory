# Key Inventory Management System

A comprehensive GitOps-based key lifecycle management system for tracking cryptographic keys, API keys, and secrets. This open source project helps companies in the payments and fintech world manage an inventory of their keys using centralized best practices and standard methods that cover all parts of the key lifecycle.

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Git
- GitHub CLI (optional, for advanced operations)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/key-inventory.git
cd key-inventory
```

2. Build the key inventory data:
```bash
python build-data.py
```

3. Serve the web interface locally:
```bash
python -m http.server 8000 --directory docs
```

The web interface will be available at http://localhost:8000

## 📋 Features

- **GitOps Workflow**: Git serves as the single source of truth
- **Automated Validation**: Schema validation, duplicate detection, and compliance checks
- **Web Interface**: Modern dashboard with search, filtering, and real-time updates
- **Comprehensive Audit Trail**: All changes tracked and auditable
- **Role-Based Access Control**: Principle of least privilege
- **Automated Compliance**: Built-in PCI DSS, SOX, GDPR, and NIST compliance
- **Key Lifecycle Management**: Automated rotation, emergency replacement
- **Multi-Cloud Support**: AWS KMS, Azure Key Vault, HashiCorp Vault
- **Monitoring & Alerting**: Real-time monitoring with customizable alerts

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              GitHub Repository                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐           │
│  │   inventory/    │    │   .github/      │    │     docs/       │           │
│  │  ├─ key1.yaml   │    │  └─ workflows/  │    │  ├─ index.html  │           │
│  │  ├─ key2.yaml   │    │     ├─ create   │    │  ├─ keys.json   │           │
│  │  └─ key3.yaml   │    │     ├─ delete   │    │  └─ audit.html  │           │
│  └─────────────────┘    │     ├─ rotate   │    └─────────────────┘           │
│                         │     └─ emergency│                                   │
│                         └─────────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
key-inventory/
├── inventory/           # YAML key definition files (one per key)
├── docs/               # Web interface and generated data
│   ├── index.html      # Main web interface
│   └── keys.json       # Generated from YAML files
├── .github/workflows/  # GitHub Actions for automation
├── scripts/           # Python scripts for key operations
├── build-data.py      # Build script to generate JSON
├── CLAUDE.md         # Claude Code instructions
└── README.md         # This file
```

## 🔑 Key Schema

Each key in the inventory follows this YAML structure:

```yaml
# Required fields
key_id: <UUID v4>
alias: <descriptive-name>
environment: <dev|staging|prod>
owner: <team-email>
purpose: <description>
created_at: <ISO-8601-timestamp>
rotation_interval_days: <integer>
location: <key-management-system-uri>

# Compliance
compliance:
  pci_scope: <none|cardholder-data|out-of-scope>
  nist_classification: <internal|confidential|secret|top-secret>
  sox_applicable: <boolean>
  gdpr_applicable: <boolean>

# Tags for categorization
tags: [<array-of-tags>]
```

### Example Key Definition

```yaml
# inventory/payment-service-jwt-prod.yaml
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

tags: [jwt, payments, pci, production, high-risk]
```

## 🔄 Key Lifecycle Operations

### 1. Creating a New Key
1. Create a new YAML file in the `inventory/` directory
2. Create a feature branch and submit a pull request
3. Automated validation runs (schema, duplicates, compliance)
4. Key-inventory admin reviews and approves
5. Automated provisioning in target key store

### 2. Deleting a Key
1. Initiate deletion via web interface or remove YAML file
2. Automated branch creation with deletion request
3. Pull request created with deletion justification
4. Admin approval required
5. Automated key revocation in target store

### 3. Key Rotation
1. Automated monitoring detects rotation due date
2. Notification sent to key owner
3. Grace period for manual rotation
4. Automated rotation if no manual action
5. New key provisioned, old key deprecated

### 4. Emergency Key Replacement
1. Emergency workflow triggered manually
2. Immediate key revocation in target store
3. New key provisioned with emergency metadata
4. Incident tracking and documentation

## 🛠️ Build Commands

### Enhanced Build Script

The `build-data.py` script provides comprehensive functionality:

```bash
# Basic build
python build-data.py

# Validation without output
python build-data.py --dry-run --verbose

# Include build statistics
python build-data.py --include-metadata

# Skip backup creation
python build-data.py --no-backup

# Show all options
python build-data.py --help
```

**Enhanced features:**
- Comprehensive schema validation with detailed error reporting
- Duplicate detection for key IDs and aliases
- Data normalization and consistency checks
- Build statistics and summary reporting
- Automatic backup of previous builds
- Verbose logging and debugging options

## 🔐 Security & Compliance

### Supported Compliance Frameworks
- **PCI DSS**: Payment card industry data security
- **SOX**: Sarbanes-Oxley Act compliance
- **GDPR**: General Data Protection Regulation
- **NIST**: National Institute of Standards and Technology

### Role-Based Access Control

| Operation | Developer | Key Owner | Security Team | Key-Inventory Admin |
|-----------|-----------|-----------|---------------|-------------------|
| Create Key | Request | N/A | Review | **Approve** |
| Delete Key | Request | Request | Review | **Approve** |
| Rotate Key | Request | Request | Review | **Approve** |
| Emergency Replace | N/A | Request | **Approve** | **Approve** |

## 🚨 Emergency Procedures

### Key Compromise Response
1. **Assessment** (0-15 min): Validate compromise and determine scope
2. **Containment** (15-30 min): Revoke key and isolate systems
3. **Recovery** (30-60 min): Generate new keys and restore operations
4. **Communication** (Ongoing): Notify stakeholders and document

### Emergency Contacts
- Security Team: security-team@company.com
- Key Admins: key-admins@company.com
- Compliance: compliance@company.com

## 📊 Monitoring & Alerting

The system provides comprehensive monitoring for:
- Key rotation status
- Compliance violations
- Security events
- Key store health
- Unauthorized access attempts

Alerts are sent via:
- Slack notifications
- Email alerts
- PagerDuty integration
- SMS for critical incidents

## 🤖 AI Agent Integration

This system is designed to be AI-agent friendly with:
- Structured YAML schema
- Clear documentation
- Automated workflows
- Comprehensive context files
- Everything-as-code approach

## 🚀 Deployment

### GitHub Repository Setup
1. Configure branch protection rules
2. Set up required teams and permissions
3. Configure GitHub Actions environments
4. Set up external service integrations

### External Service Integration
- **AWS KMS**: Configure IAM roles and policies
- **Azure Key Vault**: Set up service principals
- **HashiCorp Vault**: Configure authentication methods
- **Monitoring**: Set up Grafana/DataDog/Prometheus dashboards

## 📚 Documentation

For detailed information, see:
- [KEY_LIFECYCLE_MANAGEMENT.md](KEY_LIFECYCLE_MANAGEMENT.md) - Comprehensive system documentation
- [CLAUDE.md](CLAUDE.md) - Claude Code instructions and project context
- Web interface documentation at `/docs/`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the established coding standards
4. Submit a pull request with tests
5. Ensure all compliance checks pass

## 📄 License

This project is open source. Please refer to the LICENSE file for details.

## 🆘 Support

For questions or support:
- Create an issue in the GitHub repository
- Contact the key inventory administrators
- Refer to the emergency contacts for urgent matters

---

**Note**: This system is designed for enterprise use in regulated industries. Ensure proper security reviews and compliance validations before deploying in production environments.