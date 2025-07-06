#!/usr/bin/env python3
"""
Enhanced Key Inventory Data Builder

Validates and converts YAML key inventory files to JSON format with improved
error handling, validation, and reporting capabilities.
"""

import os
import sys
import json
import yaml
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
import uuid
import re


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom validation error."""
    pass


class BuildStatistics:
    """Enhanced statistics about the build process."""
    
    def __init__(self):
        self.total_files = 0
        self.valid_keys = 0
        self.invalid_keys = 0
        self.duplicate_keys = 0
        self.errors = []
        self.warnings = []
        self.environment_counts = defaultdict(int)
        self.compliance_counts = defaultdict(int)
        # Enhanced statistics
        self.key_type_counts = defaultdict(int)
        self.key_store_counts = defaultdict(int)
        self.lifecycle_status_counts = defaultdict(int)
        self.risk_assessment_counts = defaultdict(int)
        self.rotation_due_counts = defaultdict(int)
        self.compliance_status_counts = defaultdict(int)
        self.enhanced_schema_count = 0
        self.legacy_schema_count = 0


def validate_uuid(value: str) -> bool:
    """Validate UUID format."""
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def validate_email(value: str) -> bool:
    """Basic email validation - relaxed for internal domains."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$'
    return re.match(pattern, value) is not None


def validate_datetime_iso(value: str) -> bool:
    """Validate ISO 8601 datetime format."""
    try:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
        return True
    except ValueError:
        return False


def normalize_tags(tags: List[str]) -> List[str]:
    """Normalize and validate tags."""
    if not isinstance(tags, list):
        raise ValidationError("tags must be a list")
    
    normalized = []
    for tag in tags:
        if not isinstance(tag, str):
            raise ValidationError(f"Tag must be a string, got {type(tag)}")
        
        if not re.match(r'^[a-zA-Z0-9\-_]+$', tag):
            raise ValidationError(f"Tag '{tag}' contains invalid characters")
        
        normalized.append(tag.lower())
    
    if len(normalized) != len(set(normalized)):
        raise ValidationError("Duplicate tags are not allowed")
    
    return normalized


def validate_enhanced_key_schema(data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Validate key data against enhanced schema v2.0."""
    errors = []
    
    # Required fields for enhanced schema
    required_fields = ['key_id', 'alias', 'environment', 'owner', 'purpose', 
                      'created_at', 'rotation_interval_days', 'location', 'compliance', 'tags']
    
    for field in required_fields:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    
    if errors:
        raise ValidationError("; ".join(errors))
    
    # Validate key_id
    if not validate_uuid(data['key_id']):
        errors.append("key_id must be a valid UUID")
    
    # Validate alias
    if not re.match(r'^[a-zA-Z0-9\-_]+$', data['alias']):
        errors.append("alias can only contain alphanumeric characters, dashes, and underscores")
    
    # Validate environment (enhanced list)
    valid_envs = ['dev', 'stage', 'staging', 'prod', 'production']
    if data['environment'] not in valid_envs:
        errors.append(f"environment must be one of: {', '.join(valid_envs)}")
    
    # Validate owner email
    if not validate_email(data['owner']):
        errors.append("owner must be a valid email address")
    
    # Validate created_at
    if not validate_datetime_iso(data['created_at']):
        errors.append("created_at must be a valid ISO 8601 datetime")
    
    # Validate rotation_interval_days
    try:
        rotation_days = int(data['rotation_interval_days'])
        if rotation_days <= 0 or rotation_days > 3650:
            errors.append("rotation_interval_days must be between 1 and 3650")
    except (ValueError, TypeError):
        errors.append("rotation_interval_days must be an integer")
    
    # Validate compliance (enhanced)
    if not isinstance(data['compliance'], dict):
        errors.append("compliance must be an object")
    else:
        # Required compliance fields
        if 'pci_scope' not in data['compliance']:
            errors.append("compliance.pci_scope is required")
        elif data['compliance']['pci_scope'] not in ['none', 'cardholder-data', 'out-of-scope']:
            errors.append("compliance.pci_scope must be 'none', 'cardholder-data', or 'out-of-scope'")
        
        if 'nist_classification' not in data['compliance']:
            errors.append("compliance.nist_classification is required")
        elif data['compliance']['nist_classification'] not in ['internal', 'confidential', 'secret', 'top-secret']:
            errors.append("compliance.nist_classification must be 'internal', 'confidential', 'secret', or 'top-secret'")
        
        # Optional compliance fields validation
        if 'retention_period_days' in data['compliance']:
            try:
                retention_days = int(data['compliance']['retention_period_days'])
                if retention_days <= 0:
                    errors.append("compliance.retention_period_days must be positive")
            except (ValueError, TypeError):
                errors.append("compliance.retention_period_days must be an integer")
    
    # Validate enhanced optional sections
    if 'lifecycle' in data:
        lifecycle_errors = validate_lifecycle_section(data['lifecycle'])
        errors.extend(lifecycle_errors)
    
    if 'technical' in data:
        technical_errors = validate_technical_section(data['technical'])
        errors.extend(technical_errors)
    
    if 'relationships' in data:
        relationship_errors = validate_relationships_section(data['relationships'])
        errors.extend(relationship_errors)
    
    if 'operational' in data:
        operational_errors = validate_operational_section(data['operational'])
        errors.extend(operational_errors)
    
    if 'audit' in data:
        audit_errors = validate_audit_section(data['audit'])
        errors.extend(audit_errors)
    
    if 'metadata' in data:
        metadata_errors = validate_metadata_section(data['metadata'])
        errors.extend(metadata_errors)
    
    # Validate and normalize tags
    try:
        data['tags'] = normalize_tags(data['tags'])
    except ValidationError as e:
        errors.append(str(e))
    
    if errors:
        raise ValidationError("; ".join(errors))
    
    # Normalize data (don't lowercase alias to preserve readability)
    data['owner'] = data['owner'].lower()
    data['environment'] = data['environment'].lower()
    
    return data


def validate_lifecycle_section(lifecycle: Dict[str, Any]) -> List[str]:
    """Validate lifecycle section of enhanced schema."""
    errors = []
    
    if 'status' in lifecycle:
        valid_statuses = ['active', 'deprecated', 'revoked', 'emergency-replaced']
        if lifecycle['status'] not in valid_statuses:
            errors.append(f"lifecycle.status must be one of: {', '.join(valid_statuses)}")
    
    # Validate GitHub usernames
    username_fields = ['created_by', 'approved_by']
    for field in username_fields:
        if field in lifecycle:
            if not re.match(r'^[a-zA-Z0-9\-_.]+$', lifecycle[field]):
                errors.append(f"lifecycle.{field} must be a valid GitHub username")
    
    # Validate datetime fields
    datetime_fields = ['approved_at', 'last_rotated_at', 'next_rotation_due']
    for field in datetime_fields:
        if field in lifecycle:
            if not validate_datetime_iso(lifecycle[field]):
                errors.append(f"lifecycle.{field} must be a valid ISO 8601 datetime")
    
    # Validate rotation_count
    if 'rotation_count' in lifecycle:
        try:
            count = int(lifecycle['rotation_count'])
            if count < 0:
                errors.append("lifecycle.rotation_count must be non-negative")
        except (ValueError, TypeError):
            errors.append("lifecycle.rotation_count must be an integer")
    
    # Validate emergency_contact
    if 'emergency_contact' in lifecycle:
        if not validate_email(lifecycle['emergency_contact']):
            errors.append("lifecycle.emergency_contact must be a valid email address")
    
    return errors


def validate_technical_section(technical: Dict[str, Any]) -> List[str]:
    """Validate technical section of enhanced schema."""
    errors = []
    
    if 'key_type' in technical:
        valid_types = ['rsa', 'ec', 'symmetric', 'api-key', 'jwt']
        if technical['key_type'] not in valid_types:
            errors.append(f"technical.key_type must be one of: {', '.join(valid_types)}")
    
    if 'key_size' in technical:
        try:
            size = int(technical['key_size'])
            if size <= 0:
                errors.append("technical.key_size must be positive")
        except (ValueError, TypeError):
            errors.append("technical.key_size must be an integer")
    
    if 'key_store_type' in technical:
        valid_stores = ['aws-kms', 'azure-kv', 'hashicorp-vault', 'custom']
        if technical['key_store_type'] not in valid_stores:
            errors.append(f"technical.key_store_type must be one of: {', '.join(valid_stores)}")
    
    return errors


def validate_relationships_section(relationships: Dict[str, Any]) -> List[str]:
    """Validate relationships section of enhanced schema."""
    errors = []
    
    # Validate array fields
    array_fields = ['depends_on', 'used_by', 'related_keys', 'environments']
    for field in array_fields:
        if field in relationships:
            if not isinstance(relationships[field], list):
                errors.append(f"relationships.{field} must be an array")
            else:
                for item in relationships[field]:
                    if not isinstance(item, str):
                        errors.append(f"All items in relationships.{field} must be strings")
    
    return errors


def validate_operational_section(operational: Dict[str, Any]) -> List[str]:
    """Validate operational section of enhanced schema."""
    errors = []
    
    # Validate boolean fields
    boolean_fields = ['monitoring_enabled', 'alerting_enabled', 'auto_rotation_enabled', 'emergency_revocation_enabled']
    for field in boolean_fields:
        if field in operational:
            if not isinstance(operational[field], bool):
                errors.append(f"operational.{field} must be a boolean")
    
    return errors


def validate_audit_section(audit: Dict[str, Any]) -> List[str]:
    """Validate audit section of enhanced schema."""
    errors = []
    
    # Validate boolean fields
    boolean_fields = ['access_logs_enabled', 'usage_tracking_enabled', 'compliance_scan_enabled']
    for field in boolean_fields:
        if field in audit:
            if not isinstance(audit[field], bool):
                errors.append(f"audit.{field} must be a boolean")
    
    # Validate datetime fields
    if 'last_compliance_check' in audit:
        if not validate_datetime_iso(audit['last_compliance_check']):
            errors.append("audit.last_compliance_check must be a valid ISO 8601 datetime")
    
    # Validate compliance_status
    if 'compliance_status' in audit:
        valid_statuses = ['compliant', 'non-compliant', 'needs-review']
        if audit['compliance_status'] not in valid_statuses:
            errors.append(f"audit.compliance_status must be one of: {', '.join(valid_statuses)}")
    
    return errors


def validate_metadata_section(metadata: Dict[str, Any]) -> List[str]:
    """Validate metadata section of enhanced schema."""
    errors = []
    
    if 'risk_assessment' in metadata:
        valid_risks = ['low', 'medium', 'high', 'critical']
        if metadata['risk_assessment'] not in valid_risks:
            errors.append(f"metadata.risk_assessment must be one of: {', '.join(valid_risks)}")
    
    return errors


# Keep backward compatibility with old function name
def validate_key_schema(data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Backward compatibility wrapper for enhanced schema validation."""
    return validate_enhanced_key_schema(data, filename)


class KeyInventoryBuilder:
    """Enhanced key inventory builder with validation."""
    
    def __init__(self, input_dir: str = "inventory", output_file: str = "docs/keys.json"):
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        self.stats = BuildStatistics()
        self.seen_key_ids: Set[str] = set()
        self.seen_aliases: Set[str] = set()
    
    def validate_directories(self) -> bool:
        """Validate that required directories exist."""
        if not self.input_dir.exists():
            logger.error(f"Input directory '{self.input_dir}' does not exist")
            return False
        
        if not self.input_dir.is_dir():
            logger.error(f"Input path '{self.input_dir}' is not a directory")
            return False
        
        # Create output directory if it doesn't exist
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        return True
    
    def backup_previous_build(self) -> bool:
        """Create backup of previous build if it exists."""
        if not self.output_file.exists():
            return True
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.output_file.with_suffix(f".{timestamp}.backup")
        
        try:
            shutil.copy2(self.output_file, backup_file)
            logger.info(f"Created backup: {backup_file}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create backup: {e}")
            return False
    
    def load_and_validate_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load and validate a single YAML file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_data = yaml.safe_load(f)
            
            if not raw_data:
                self.stats.errors.append(f"{file_path.name}: File is empty")
                return None
            
            # Validate schema
            key_data = validate_key_schema(raw_data, file_path.name)
            
            # Check for duplicates
            if key_data['key_id'] in self.seen_key_ids:
                self.stats.errors.append(f"{file_path.name}: Duplicate key_id '{key_data['key_id']}'")
                self.stats.duplicate_keys += 1
                return None
            
            if key_data['alias'] in self.seen_aliases:
                self.stats.warnings.append(f"{file_path.name}: Duplicate alias '{key_data['alias']}'")
            
            self.seen_key_ids.add(key_data['key_id'])
            self.seen_aliases.add(key_data['alias'])
            
            # Update enhanced statistics
            self.stats.environment_counts[key_data['environment']] += 1
            self.stats.compliance_counts[key_data['compliance']['nist_classification']] += 1
            
            # Enhanced schema statistics
            if any(field in key_data for field in ['lifecycle', 'technical', 'relationships', 'operational', 'audit', 'metadata']):
                self.stats.enhanced_schema_count += 1
            else:
                self.stats.legacy_schema_count += 1
            
            # Technical statistics
            if 'technical' in key_data:
                technical = key_data['technical']
                if 'key_type' in technical:
                    self.stats.key_type_counts[technical['key_type']] += 1
                if 'key_store_type' in technical:
                    self.stats.key_store_counts[technical['key_store_type']] += 1
            
            # Lifecycle statistics
            if 'lifecycle' in key_data:
                lifecycle = key_data['lifecycle']
                status = lifecycle.get('status', 'active')
                self.stats.lifecycle_status_counts[status] += 1
            else:
                self.stats.lifecycle_status_counts['active'] += 1  # Default for legacy
            
            # Risk assessment statistics
            if 'metadata' in key_data and 'risk_assessment' in key_data['metadata']:
                risk = key_data['metadata']['risk_assessment']
                self.stats.risk_assessment_counts[risk] += 1
            
            # Compliance status statistics
            if 'audit' in key_data and 'compliance_status' in key_data['audit']:
                status = key_data['audit']['compliance_status']
                self.stats.compliance_status_counts[status] += 1
            
            return key_data
            
        except yaml.YAMLError as e:
            self.stats.errors.append(f"{file_path.name}: YAML parsing error - {e}")
            return None
        except ValidationError as e:
            self.stats.errors.append(f"{file_path.name}: Validation error - {e}")
            return None
        except Exception as e:
            self.stats.errors.append(f"{file_path.name}: Unexpected error - {e}")
            return None
    
    def process_inventory(self) -> List[Dict[str, Any]]:
        """Process all YAML files in the inventory directory."""
        valid_keys = []
        yaml_files = list(self.input_dir.glob("*.yaml")) + list(self.input_dir.glob("*.yml"))
        
        if not yaml_files:
            logger.warning(f"No YAML files found in {self.input_dir}")
            return valid_keys
        
        self.stats.total_files = len(yaml_files)
        logger.info(f"Processing {self.stats.total_files} YAML files...")
        
        for file_path in sorted(yaml_files):
            logger.debug(f"Processing {file_path.name}")
            
            key_data = self.load_and_validate_file(file_path)
            if key_data:
                valid_keys.append(key_data)
                self.stats.valid_keys += 1
            else:
                self.stats.invalid_keys += 1
        
        # Sort keys by creation date (newest first)
        valid_keys.sort(key=lambda x: x['created_at'], reverse=True)
        
        return valid_keys
    
    def generate_build_metadata(self) -> Dict[str, Any]:
        """Generate enhanced metadata about the build process."""
        return {
            "build_timestamp": datetime.now().isoformat(),
            "schema_version": "2.0",
            "total_keys": self.stats.valid_keys,
            "statistics": {
                "by_environment": dict(self.stats.environment_counts),
                "by_compliance": dict(self.stats.compliance_counts),
                "by_key_type": dict(self.stats.key_type_counts),
                "by_key_store": dict(self.stats.key_store_counts),
                "by_lifecycle_status": dict(self.stats.lifecycle_status_counts),
                "by_risk_assessment": dict(self.stats.risk_assessment_counts),
                "by_compliance_status": dict(self.stats.compliance_status_counts),
                "schema_usage": {
                    "enhanced_schema_v2": self.stats.enhanced_schema_count,
                    "legacy_schema_v1": self.stats.legacy_schema_count
                },
                "totals": {
                    "total_files_processed": self.stats.total_files,
                    "valid_keys": self.stats.valid_keys,
                    "invalid_keys": self.stats.invalid_keys,
                    "duplicate_keys": self.stats.duplicate_keys
                }
            },
            "build_info": {
                "errors": len(self.stats.errors),
                "warnings": len(self.stats.warnings),
                "success_rate": round((self.stats.valid_keys / max(self.stats.total_files, 1)) * 100, 2)
            }
        }
    
    def write_output(self, keys: List[Dict[str, Any]], include_metadata: bool = False) -> bool:
        """Write the processed keys to JSON file."""
        try:
            output_data = keys
            
            if include_metadata:
                output_data = {
                    "metadata": self.generate_build_metadata(),
                    "keys": keys
                }
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Successfully wrote {len(keys)} keys to {self.output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")
            return False
    
    def print_summary(self, verbose: bool = False):
        """Print a summary of the build process."""
        print(f"\n{'='*60}")
        print(f"Key Inventory Build Summary")
        print(f"{'='*60}")
        
        print(f"\n✓ Files processed: {self.stats.total_files}")
        print(f"✓ Valid keys: {self.stats.valid_keys}")
        
        if self.stats.invalid_keys > 0:
            print(f"✗ Invalid keys: {self.stats.invalid_keys}")
        
        if self.stats.duplicate_keys > 0:
            print(f"⚠ Duplicate keys: {self.stats.duplicate_keys}")
        
        # Schema usage
        if self.stats.enhanced_schema_count > 0 or self.stats.legacy_schema_count > 0:
            print(f"\nSchema Usage:")
            print(f"  Enhanced Schema v2.0: {self.stats.enhanced_schema_count}")
            print(f"  Legacy Schema v1.0: {self.stats.legacy_schema_count}")
        
        # Environment breakdown
        if self.stats.environment_counts:
            print(f"\nEnvironment Distribution:")
            for env, count in sorted(self.stats.environment_counts.items()):
                print(f"  {env}: {count}")
        
        # Compliance breakdown
        if self.stats.compliance_counts:
            print(f"\nCompliance Distribution:")
            for compliance, count in sorted(self.stats.compliance_counts.items()):
                print(f"  {compliance}: {count}")
        
        # Enhanced statistics (shown only in verbose mode)
        if verbose:
            if self.stats.key_type_counts:
                print(f"\nKey Types:")
                for key_type, count in sorted(self.stats.key_type_counts.items()):
                    print(f"  {key_type}: {count}")
            
            if self.stats.key_store_counts:
                print(f"\nKey Stores:")
                for store, count in sorted(self.stats.key_store_counts.items()):
                    print(f"  {store}: {count}")
            
            if self.stats.lifecycle_status_counts:
                print(f"\nLifecycle Status:")
                for status, count in sorted(self.stats.lifecycle_status_counts.items()):
                    print(f"  {status}: {count}")
            
            if self.stats.risk_assessment_counts:
                print(f"\nRisk Assessment:")
                for risk, count in sorted(self.stats.risk_assessment_counts.items()):
                    print(f"  {risk}: {count}")
            
            if self.stats.compliance_status_counts:
                print(f"\nCompliance Status:")
                for status, count in sorted(self.stats.compliance_status_counts.items()):
                    print(f"  {status}: {count}")
        
        # Errors and warnings
        if self.stats.errors:
            print(f"\nErrors ({len(self.stats.errors)}):")
            for error in self.stats.errors[:10]:  # Limit to first 10 errors
                print(f"  ✗ {error}")
            if len(self.stats.errors) > 10:
                print(f"  ... and {len(self.stats.errors) - 10} more errors")
        
        if self.stats.warnings and verbose:
            print(f"\nWarnings ({len(self.stats.warnings)}):")
            for warning in self.stats.warnings[:5]:  # Limit to first 5 warnings
                print(f"  ⚠ {warning}")
            if len(self.stats.warnings) > 5:
                print(f"  ... and {len(self.stats.warnings) - 5} more warnings")
        
        print(f"\n{'='*60}")
    
    def build(self, backup: bool = True, include_metadata: bool = False, verbose: bool = False) -> bool:
        """Main build process."""
        logger.info("Starting enhanced key inventory build...")
        
        # Validate directories
        if not self.validate_directories():
            return False
        
        # Backup previous build
        if backup:
            self.backup_previous_build()
        
        # Process inventory
        valid_keys = self.process_inventory()
        
        # Write output
        if not self.write_output(valid_keys, include_metadata):
            return False
        
        # Print summary
        self.print_summary(verbose)
        
        # Return success/failure based on whether we have valid keys and no critical errors
        success = self.stats.valid_keys > 0 and self.stats.invalid_keys == 0
        
        if not success:
            logger.error("Build completed with errors")
        else:
            logger.info("Build completed successfully")
        
        return success


def main():
    """Main entry point with basic argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Key Inventory Data Builder')
    parser.add_argument('--input-dir', '-i', default='inventory',
                      help='Input directory containing YAML files (default: inventory)')
    parser.add_argument('--output-file', '-o', default='docs/keys.json',
                      help='Output JSON file path (default: docs/keys.json)')
    parser.add_argument('--no-backup', action='store_true',
                      help='Skip creating backup of previous build')
    parser.add_argument('--include-metadata', action='store_true',
                      help='Include build metadata in output file')
    parser.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose output including warnings')
    parser.add_argument('--dry-run', action='store_true',
                      help='Validate files without generating output')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                      default='INFO', help='Set logging level')
    
    args = parser.parse_args()
    
    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    if args.verbose:
        print("Enhanced Key Inventory Data Builder")
        print(f"Input directory: {args.input_dir}")
        print(f"Output file: {args.output_file}")
        if args.dry_run:
            print("Running in dry-run mode (no output will be generated)")
    
    builder = KeyInventoryBuilder(args.input_dir, args.output_file)
    
    if args.dry_run:
        # Just validate, don't write output
        builder.validate_directories()
        builder.process_inventory()
        builder.print_summary(args.verbose)
        
        # Exit with error code if validation failed
        sys.exit(0 if builder.stats.invalid_keys == 0 else 1)
    else:
        # Full build process
        success = builder.build(
            backup=not args.no_backup,
            include_metadata=args.include_metadata,
            verbose=args.verbose
        )
        
        # Exit with appropriate code for CI/CD
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()