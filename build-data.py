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
    """Statistics about the build process."""
    
    def __init__(self):
        self.total_files = 0
        self.valid_keys = 0
        self.invalid_keys = 0
        self.duplicate_keys = 0
        self.errors = []
        self.warnings = []
        self.environment_counts = defaultdict(int)
        self.compliance_counts = defaultdict(int)


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


def validate_key_schema(data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Validate key data against schema."""
    errors = []
    
    # Required fields
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
    
    # Validate environment (accept both 'stage' and 'staging')
    if data['environment'] not in ['dev', 'stage', 'staging', 'prod']:
        errors.append("environment must be 'dev', 'stage', 'staging', or 'prod'")
    
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
    
    # Validate compliance
    if not isinstance(data['compliance'], dict):
        errors.append("compliance must be an object")
    else:
        if 'pci_scope' not in data['compliance']:
            errors.append("compliance.pci_scope is required")
        elif data['compliance']['pci_scope'] not in ['none', 'cardholder-data', 'out-of-scope']:
            errors.append("compliance.pci_scope must be 'none', 'cardholder-data', or 'out-of-scope'")
        
        if 'nist_classification' not in data['compliance']:
            errors.append("compliance.nist_classification is required")
        elif data['compliance']['nist_classification'] not in ['internal', 'confidential', 'secret', 'top-secret']:
            errors.append("compliance.nist_classification must be 'internal', 'confidential', 'secret', or 'top-secret'")
    
    # Validate and normalize tags
    try:
        data['tags'] = normalize_tags(data['tags'])
    except ValidationError as e:
        errors.append(str(e))
    
    if errors:
        raise ValidationError("; ".join(errors))
    
    # Normalize data
    data['alias'] = data['alias'].lower()
    data['owner'] = data['owner'].lower()
    data['environment'] = data['environment'].lower()
    
    return data


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
            
            # Update statistics
            self.stats.environment_counts[key_data['environment']] += 1
            self.stats.compliance_counts[key_data['compliance']['nist_classification']] += 1
            
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
        """Generate metadata about the build process."""
        return {
            "build_timestamp": datetime.now().isoformat(),
            "total_keys": self.stats.valid_keys,
            "statistics": {
                "by_environment": dict(self.stats.environment_counts),
                "by_compliance": dict(self.stats.compliance_counts),
                "total_files_processed": self.stats.total_files,
                "valid_keys": self.stats.valid_keys,
                "invalid_keys": self.stats.invalid_keys,
                "duplicate_keys": self.stats.duplicate_keys
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