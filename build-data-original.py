#!/usr/bin/env python3
"""
Key Inventory Data Builder

Validates and converts YAML key inventory files to JSON format with comprehensive
schema validation, error handling, and reporting capabilities.
"""

import os
import sys
import json
import yaml
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from collections import Counter, defaultdict
from dataclasses import dataclass
import uuid
import re

try:
    from pydantic import BaseModel, Field, validator, ValidationError
    from pydantic.types import EmailStr
    import click
    from colorama import init, Fore, Style
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install dependencies with: pip install pydantic click colorama")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class BuildStatistics:
    """Statistics about the build process."""
    total_files: int = 0
    valid_keys: int = 0
    invalid_keys: int = 0
    duplicate_keys: int = 0
    errors: List[str] = None
    warnings: List[str] = None
    environment_counts: Dict[str, int] = None
    compliance_counts: Dict[str, int] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.environment_counts is None:
            self.environment_counts = defaultdict(int)
        if self.compliance_counts is None:
            self.compliance_counts = defaultdict(int)


class ComplianceModel(BaseModel):
    """Compliance information for cryptographic keys."""
    pci_scope: str = Field(..., regex=r'^(none|cardholder-data|out-of-scope)$')
    nist_classification: str = Field(..., regex=r'^(internal|confidential|secret|top-secret)$')


class KeyInventoryModel(BaseModel):
    """Pydantic model for validating key inventory data."""
    key_id: str = Field(..., min_length=36, max_length=36)
    alias: str = Field(..., min_length=1, max_length=100)
    environment: str = Field(..., regex=r'^(dev|staging|prod)$')
    owner: EmailStr
    purpose: str = Field(..., min_length=1, max_length=500)
    created_at: datetime
    rotation_interval_days: int = Field(..., gt=0, le=3650)  # Max 10 years
    location: str = Field(..., min_length=1)
    compliance: ComplianceModel
    tags: List[str] = Field(..., min_items=1)
    
    @validator('key_id')
    def validate_key_id_format(cls, v):
        """Validate that key_id is a properly formatted UUID."""
        try:
            uuid.UUID(v)
        except ValueError:
            raise ValueError('key_id must be a valid UUID format')
        return v
    
    @validator('created_at')
    def validate_created_at_not_future(cls, v):
        """Ensure created_at is not in the future."""
        if v > datetime.now(timezone.utc):
            raise ValueError('created_at cannot be in the future')
        return v
    
    @validator('owner')
    def validate_owner_domain(cls, v):
        """Normalize owner email to lowercase."""
        return v.lower()
    
    @validator('tags')
    def validate_tags_format(cls, v):
        """Validate and normalize tags."""
        normalized_tags = []
        for tag in v:
            if not isinstance(tag, str):
                raise ValueError(f'Tag must be a string, got {type(tag)}')
            if not re.match(r'^[a-zA-Z0-9\-_]+$', tag):
                raise ValueError(f'Tag "{tag}" contains invalid characters. Use only alphanumeric, dash, and underscore.')
            normalized_tags.append(tag.lower())
        
        # Check for duplicates
        if len(normalized_tags) != len(set(normalized_tags)):
            raise ValueError('Duplicate tags are not allowed')
        
        return normalized_tags
    
    @validator('alias')
    def validate_alias_format(cls, v):
        """Validate alias format and normalize."""
        if not re.match(r'^[a-zA-Z0-9\-_]+$', v):
            raise ValueError('Alias can only contain alphanumeric characters, dashes, and underscores')
        return v.lower()
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class KeyInventoryBuilder:
    """Main class for building and validating key inventory data."""
    
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
    
    def load_and_validate_file(self, file_path: Path) -> Optional[KeyInventoryModel]:
        """Load and validate a single YAML file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_data = yaml.safe_load(f)
            
            if not raw_data:
                self.stats.errors.append(f"{file_path.name}: File is empty")
                return None
            
            # Validate with Pydantic
            key_data = KeyInventoryModel(**raw_data)
            
            # Check for duplicates
            if key_data.key_id in self.seen_key_ids:
                self.stats.errors.append(f"{file_path.name}: Duplicate key_id '{key_data.key_id}'")
                self.stats.duplicate_keys += 1
                return None
            
            if key_data.alias in self.seen_aliases:
                self.stats.warnings.append(f"{file_path.name}: Duplicate alias '{key_data.alias}'")
            
            self.seen_key_ids.add(key_data.key_id)
            self.seen_aliases.add(key_data.alias)
            
            # Update statistics
            self.stats.environment_counts[key_data.environment] += 1
            self.stats.compliance_counts[key_data.compliance.nist_classification] += 1
            
            return key_data
            
        except yaml.YAMLError as e:
            self.stats.errors.append(f"{file_path.name}: YAML parsing error - {e}")
            return None
        except ValidationError as e:
            error_details = []
            for error in e.errors():
                field = '.'.join(str(x) for x in error['loc'])
                error_details.append(f"{field}: {error['msg']}")
            self.stats.errors.append(f"{file_path.name}: Validation error - {'; '.join(error_details)}")
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
                valid_keys.append(key_data.dict())
                self.stats.valid_keys += 1
            else:
                self.stats.invalid_keys += 1
        
        # Sort keys by creation date (newest first)
        valid_keys.sort(key=lambda x: x['created_at'], reverse=True)
        
        return valid_keys
    
    def generate_build_metadata(self) -> Dict[str, Any]:
        """Generate metadata about the build process."""
        return {
            "build_timestamp": datetime.now(timezone.utc).isoformat(),
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
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Key Inventory Build Summary")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.GREEN}✓ Files processed: {self.stats.total_files}")
        print(f"{Fore.GREEN}✓ Valid keys: {self.stats.valid_keys}")
        
        if self.stats.invalid_keys > 0:
            print(f"{Fore.RED}✗ Invalid keys: {self.stats.invalid_keys}")
        
        if self.stats.duplicate_keys > 0:
            print(f"{Fore.YELLOW}⚠ Duplicate keys: {self.stats.duplicate_keys}")
        
        # Environment breakdown
        if self.stats.environment_counts:
            print(f"\n{Fore.BLUE}Environment Distribution:")
            for env, count in sorted(self.stats.environment_counts.items()):
                print(f"  {env}: {count}")
        
        # Compliance breakdown
        if self.stats.compliance_counts:
            print(f"\n{Fore.BLUE}Compliance Distribution:")
            for compliance, count in sorted(self.stats.compliance_counts.items()):
                print(f"  {compliance}: {count}")
        
        # Errors and warnings
        if self.stats.errors:
            print(f"\n{Fore.RED}Errors ({len(self.stats.errors)}):")
            for error in self.stats.errors[:10]:  # Limit to first 10 errors
                print(f"  {Fore.RED}✗ {error}")
            if len(self.stats.errors) > 10:
                print(f"  {Fore.RED}... and {len(self.stats.errors) - 10} more errors")
        
        if self.stats.warnings and verbose:
            print(f"\n{Fore.YELLOW}Warnings ({len(self.stats.warnings)}):")
            for warning in self.stats.warnings[:5]:  # Limit to first 5 warnings
                print(f"  {Fore.YELLOW}⚠ {warning}")
            if len(self.stats.warnings) > 5:
                print(f"  {Fore.YELLOW}... and {len(self.stats.warnings) - 5} more warnings")
        
        print(f"\n{Fore.CYAN}{'='*60}")
    
    def build(self, backup: bool = True, include_metadata: bool = False, verbose: bool = False) -> bool:
        """Main build process."""
        logger.info("Starting key inventory build...")
        
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


@click.command()
@click.option('--input-dir', '-i', default='inventory', 
              help='Input directory containing YAML files (default: inventory)')
@click.option('--output-file', '-o', default='docs/keys.json',
              help='Output JSON file path (default: docs/keys.json)')
@click.option('--no-backup', is_flag=True, 
              help='Skip creating backup of previous build')
@click.option('--include-metadata', is_flag=True,
              help='Include build metadata in output file')
@click.option('--verbose', '-v', is_flag=True,
              help='Enable verbose output including warnings')
@click.option('--dry-run', is_flag=True,
              help='Validate files without generating output')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              default='INFO', help='Set logging level')
def main(input_dir: str, output_file: str, no_backup: bool, include_metadata: bool, 
         verbose: bool, dry_run: bool, log_level: str):
    """
    Build and validate key inventory data from YAML files.
    
    This tool processes YAML files in the inventory directory, validates them
    against a comprehensive schema, and generates a JSON file for the web interface.
    """
    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, log_level))
    
    if verbose:
        click.echo(f"{Fore.CYAN}Key Inventory Data Builder")
        click.echo(f"{Fore.CYAN}Input directory: {input_dir}")
        click.echo(f"{Fore.CYAN}Output file: {output_file}")
        if dry_run:
            click.echo(f"{Fore.YELLOW}Running in dry-run mode (no output will be generated)")
    
    builder = KeyInventoryBuilder(input_dir, output_file)
    
    if dry_run:
        # Just validate, don't write output
        builder.validate_directories()
        builder.process_inventory()
        builder.print_summary(verbose)
        
        # Exit with error code if validation failed
        sys.exit(0 if builder.stats.invalid_keys == 0 else 1)
    else:
        # Full build process
        success = builder.build(
            backup=not no_backup,
            include_metadata=include_metadata,
            verbose=verbose
        )
        
        # Exit with appropriate code for CI/CD
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()