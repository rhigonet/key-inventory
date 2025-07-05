# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a key inventory management system for tracking cryptographic keys.
Key inventory is a open source project that I'm building to help companies in the payments and fintech world to manage an inventory of their keys using a centralize ways with good practices and standard methods that covers all part of the key life-cycle

## Technical dev practices

- Use standard commits
- Commit frecuently, avoid commit with big changes

## Common Commands

### Build the key inventory data
```bash
python build-data.py
```
This script reads all YAML files from the `inventory/` directory and generates `docs/keys.json` for the web interface.

### Serve the web interface locally
```bash
# Simple HTTP server for testing
python -m http.server 8000 --directory docs
```
The web interface will be available at http://localhost:8000

## Architecture

### Data Structure
- **inventory/**: Contains YAML files, each representing a single cryptographic key
- **docs/**: Contains the web interface and generated JSON data
- **build-data.py**: Python script that converts YAML inventory files to JSON

### Key Schema
Each key in the inventory follows this YAML structure:
```yaml
key_id: <UUID>
alias: <descriptive-name>
environment: <dev|staging|prod>
owner: <team-email>
purpose: <description>
created_at: <ISO-8601-timestamp>
rotation_interval_days: <integer>
location: <key-management-system-uri>
compliance:
  pci_scope: <none|cardholder-data|out-of-scope>
  nist_classification: <internal|confidential|secret|top-secret>
tags: [<array-of-tags>]
```

### Web Interface
The HTML interface provides:
- Dynamic key inventory display with card-based layout
- Search functionality (alias, owner, purpose)
- Environment filtering
- Real-time filtering without page refresh

The web interface is served as a GitHub page. The idea is that a company that has the GitHub enterprise version can expose it privately for their teams.

## File Structure
```
key-inventory/
├── inventory/           # YAML key definition files (one per key)
├── docs/               # Web interface and generated data
│   ├── index.html      # Main web interface
│   └── keys.json       # Generated from YAML files
├── build-data.py       # Build script to generate JSON
└── README.md          # Project documentation
```
