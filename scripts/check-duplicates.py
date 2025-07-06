#!/usr/bin/env python3
"""
Duplicate Check Script
Checks for duplicate key IDs and aliases in the inventory
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Set, Dict, List, Any


def load_key_file(file_path: str) -> Dict[str, Any]:
    """Load and parse a key file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not load {file_path}: {e}")
        return {}


def check_duplicates(new_files: List[str]) -> List[str]:
    """Check for duplicate key IDs and aliases."""
    errors = []
    
    # Get all existing inventory files
    inventory_dir = Path('inventory')
    if not inventory_dir.exists():
        return ["Inventory directory not found"]
    
    existing_files = list(inventory_dir.glob('*.yaml')) + list(inventory_dir.glob('*.yml'))
    
    # Load existing keys
    existing_key_ids = set()
    existing_aliases = set()
    
    for file_path in existing_files:
        # Skip files that are being added/modified in this PR
        if str(file_path) in new_files:
            continue
        
        data = load_key_file(str(file_path))
        if 'key_id' in data:
            existing_key_ids.add(data['key_id'])
        if 'alias' in data:
            existing_aliases.add(data['alias'].lower())
    
    # Check new files for duplicates
    new_key_ids = set()
    new_aliases = set()
    
    for file_path in new_files:
        if not file_path.strip():
            continue
        
        filename = os.path.basename(file_path)
        data = load_key_file(file_path)
        
        if not data:
            continue
        
        # Check key_id
        if 'key_id' in data:
            key_id = data['key_id']
            
            # Check against existing keys
            if key_id in existing_key_ids:
                errors.append(f"{filename}: Duplicate key_id '{key_id}' already exists in inventory")
            
            # Check against other new keys
            if key_id in new_key_ids:
                errors.append(f"{filename}: Duplicate key_id '{key_id}' found in multiple new files")
            else:
                new_key_ids.add(key_id)
        
        # Check alias
        if 'alias' in data:
            alias = data['alias'].lower()
            
            # Check against existing keys (warning only for aliases)
            if alias in existing_aliases:
                errors.append(f"{filename}: Warning - Alias '{data['alias']}' already exists in inventory (aliases should be unique)")
            
            # Check against other new keys
            if alias in new_aliases:
                errors.append(f"{filename}: Duplicate alias '{data['alias']}' found in multiple new files")
            else:
                new_aliases.add(alias)
    
    return errors


def check_related_keys(new_files: List[str]) -> List[str]:
    """Check if related keys exist in inventory."""
    errors = []
    
    # Get all existing key IDs
    inventory_dir = Path('inventory')
    if not inventory_dir.exists():
        return []
    
    existing_files = list(inventory_dir.glob('*.yaml')) + list(inventory_dir.glob('*.yml'))
    existing_key_ids = set()
    
    for file_path in existing_files:
        data = load_key_file(str(file_path))
        if 'key_id' in data:
            existing_key_ids.add(data['key_id'])
    
    # Add new key IDs to the set
    for file_path in new_files:
        if not file_path.strip():
            continue
        
        data = load_key_file(file_path)
        if 'key_id' in data:
            existing_key_ids.add(data['key_id'])
    
    # Check relationships in new files
    for file_path in new_files:
        if not file_path.strip():
            continue
        
        filename = os.path.basename(file_path)
        data = load_key_file(file_path)
        
        if not data:
            continue
        
        # Check relationships section
        if 'relationships' in data and isinstance(data['relationships'], dict):
            relationships = data['relationships']
            
            # Check depends_on
            if 'depends_on' in relationships and isinstance(relationships['depends_on'], list):
                for dep_key_id in relationships['depends_on']:
                    if dep_key_id not in existing_key_ids:
                        errors.append(f"{filename}: Referenced key in depends_on '{dep_key_id}' does not exist")
            
            # Check related_keys
            if 'related_keys' in relationships and isinstance(relationships['related_keys'], list):
                for related_key_id in relationships['related_keys']:
                    if related_key_id not in existing_key_ids:
                        errors.append(f"{filename}: Referenced key in related_keys '{related_key_id}' does not exist")
    
    return errors


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: check-duplicates.py <file1> [file2] ...")
        sys.exit(1)
    
    new_files = [f for f in sys.argv[1:] if f.strip()]
    
    if not new_files:
        print("No files to check")
        sys.exit(0)
    
    print(f"Checking {len(new_files)} files for duplicates...")
    
    # Check for duplicates
    duplicate_errors = check_duplicates(new_files)
    
    # Check related keys
    relationship_errors = check_related_keys(new_files)
    
    all_errors = duplicate_errors + relationship_errors
    
    # Write results to file for GitHub Actions
    with open('duplicate-check-results.txt', 'w') as f:
        if all_errors:
            f.write("❌ Duplicate Check Errors:\n\n")
            for error in all_errors:
                f.write(f"• {error}\n")
        else:
            f.write("✅ No duplicates found!\n")
    
    # Print summary
    print(f"\nDuplicate Check Summary:")
    print(f"Files checked: {len(new_files)}")
    print(f"Issues found: {len(all_errors)}")
    
    if all_errors:
        print("\nIssues:")
        for error in all_errors:
            print(f"  ❌ {error}")
        sys.exit(1)
    else:
        print("✅ No duplicates found!")
        sys.exit(0)


if __name__ == "__main__":
    main()