#!/usr/bin/env python3
"""
Key Creation Validation Script
Validates new key definitions against enhanced schema
"""

import os
import sys
import yaml
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


class ValidationError(Exception):
    """Custom validation error."""
    pass


def validate_uuid(value: str) -> bool:
    """Validate UUID format."""
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def validate_email(value: str) -> bool:
    """Basic email validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, value) is not None


def validate_datetime_iso(value: str) -> bool:
    """Validate ISO 8601 datetime format."""
    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
        return True
    except ValueError:
        return False


def validate_enhanced_key_schema(data: Dict[str, Any], filename: str) -> List[str]:
    """Validate enhanced key schema v2.0."""
    errors = []
    
    # Required fields
    required_fields = [
        'key_id', 'alias', 'environment', 'owner', 'purpose',
        'created_at', 'rotation_interval_days', 'location', 'compliance', 'tags'
    ]
    
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    
    # Validate key_id
    if 'key_id' in data:
        if not validate_uuid(data['key_id']):
            errors.append("key_id must be a valid UUID v4")
        
        # Check if filename matches key_id
        expected_filename = f"{data['key_id']}.yaml"
        if not filename.endswith(expected_filename):
            errors.append(f"Filename must match key_id: expected {expected_filename}")
    
    # Validate alias
    if 'alias' in data:
        if not re.match(r'^[a-zA-Z0-9\-_]+$', data['alias']):
            errors.append("alias can only contain alphanumeric characters, dashes, and underscores")
    
    # Validate environment
    if 'environment' in data:
        valid_envs = ['dev', 'staging', 'stage', 'prod', 'production']
        if data['environment'] not in valid_envs:
            errors.append(f"environment must be one of: {', '.join(valid_envs)}")
    
    # Validate owner
    if 'owner' in data:
        if not validate_email(data['owner']):
            errors.append("owner must be a valid email address")
    
    # Validate created_at
    if 'created_at' in data:
        if not validate_datetime_iso(data['created_at']):
            errors.append("created_at must be a valid ISO 8601 datetime")
    
    # Validate rotation_interval_days
    if 'rotation_interval_days' in data:
        try:
            rotation_days = int(data['rotation_interval_days'])
            if rotation_days <= 0 or rotation_days > 3650:
                errors.append("rotation_interval_days must be between 1 and 3650")
        except (ValueError, TypeError):
            errors.append("rotation_interval_days must be an integer")
    
    # Validate compliance (required)
    if 'compliance' in data:
        compliance = data['compliance']
        if not isinstance(compliance, dict):
            errors.append("compliance must be an object")
        else:
            # Required compliance fields
            if 'pci_scope' not in compliance:
                errors.append("compliance.pci_scope is required")
            elif compliance['pci_scope'] not in ['none', 'cardholder-data', 'out-of-scope']:
                errors.append("compliance.pci_scope must be 'none', 'cardholder-data', or 'out-of-scope'")
            
            if 'nist_classification' not in compliance:
                errors.append("compliance.nist_classification is required")
            elif compliance['nist_classification'] not in ['internal', 'confidential', 'secret', 'top-secret']:
                errors.append("compliance.nist_classification must be 'internal', 'confidential', 'secret', or 'top-secret'")
    
    # Validate tags
    if 'tags' in data:
        if not isinstance(data['tags'], list):
            errors.append("tags must be an array")
        else:
            for tag in data['tags']:
                if not isinstance(tag, str):
                    errors.append("All tags must be strings")
                elif not re.match(r'^[a-zA-Z0-9\-_]+$', tag):
                    errors.append(f"Tag '{tag}' contains invalid characters")
    
    # Validate optional enhanced fields
    if 'lifecycle' in data:
        lifecycle = data['lifecycle']
        if isinstance(lifecycle, dict):
            if 'status' in lifecycle:
                valid_statuses = ['active', 'deprecated', 'revoked', 'emergency-replaced']
                if lifecycle['status'] not in valid_statuses:
                    errors.append(f"lifecycle.status must be one of: {', '.join(valid_statuses)}")
            
            if 'created_by' in lifecycle and not re.match(r'^[a-zA-Z0-9\-_.]+$', lifecycle['created_by']):
                errors.append("lifecycle.created_by must be a valid GitHub username")
            
            if 'approved_by' in lifecycle and not re.match(r'^[a-zA-Z0-9\-_.]+$', lifecycle['approved_by']):
                errors.append("lifecycle.approved_by must be a valid GitHub username")
            
            datetime_fields = ['approved_at', 'last_rotated_at', 'next_rotation_due']
            for field in datetime_fields:
                if field in lifecycle and not validate_datetime_iso(lifecycle[field]):
                    errors.append(f"lifecycle.{field} must be a valid ISO 8601 datetime")
    
    if 'technical' in data:
        technical = data['technical']
        if isinstance(technical, dict):
            if 'key_type' in technical:
                valid_types = ['rsa', 'ec', 'symmetric', 'api-key', 'jwt']
                if technical['key_type'] not in valid_types:
                    errors.append(f"technical.key_type must be one of: {', '.join(valid_types)}")
            
            if 'key_store_type' in technical:
                valid_stores = ['aws-kms', 'azure-kv', 'hashicorp-vault', 'custom']
                if technical['key_store_type'] not in valid_stores:
                    errors.append(f"technical.key_store_type must be one of: {', '.join(valid_stores)}")
    
    if 'metadata' in data:
        metadata = data['metadata']
        if isinstance(metadata, dict):
            if 'risk_assessment' in metadata:
                valid_risks = ['low', 'medium', 'high', 'critical']
                if metadata['risk_assessment'] not in valid_risks:
                    errors.append(f"metadata.risk_assessment must be one of: {', '.join(valid_risks)}")
    
    return errors


def validate_file(file_path: str) -> List[str]:
    """Validate a single key file."""
    errors = []
    filename = os.path.basename(file_path)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            errors.append(f"{filename}: File is empty")
            return errors
        
        # Validate against enhanced schema
        schema_errors = validate_enhanced_key_schema(data, filename)
        errors.extend([f"{filename}: {error}" for error in schema_errors])
        
    except yaml.YAMLError as e:
        errors.append(f"{filename}: YAML parsing error - {e}")
    except FileNotFoundError:
        errors.append(f"{filename}: File not found")
    except Exception as e:
        errors.append(f"{filename}: Unexpected error - {e}")
    
    return errors


def main():
    """Main validation function."""
    if len(sys.argv) < 2:
        print("Usage: validate-key-creation.py <file1> [file2] ...")
        sys.exit(1)
    
    all_errors = []
    files_validated = 0
    
    for file_path in sys.argv[1:]:
        if not file_path.strip():
            continue
        
        print(f"Validating {file_path}...")
        errors = validate_file(file_path)
        all_errors.extend(errors)
        files_validated += 1
    
    # Write errors to file for GitHub Actions
    with open('validation-errors.txt', 'w') as f:
        if all_errors:
            f.write("❌ Validation Errors:\n\n")
            for error in all_errors:
                f.write(f"• {error}\n")
        else:
            f.write("✅ All validations passed!\n")
    
    # Print summary
    print(f"\nValidation Summary:")
    print(f"Files validated: {files_validated}")
    print(f"Errors found: {len(all_errors)}")
    
    if all_errors:
        print("\nErrors:")
        for error in all_errors:
            print(f"  ❌ {error}")
        sys.exit(1)
    else:
        print("✅ All validations passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()