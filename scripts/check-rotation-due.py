#!/usr/bin/env python3
"""
Key Rotation Due Check Script
Checks which keys are due for rotation and generates warnings
"""

import os
import sys
import json
import yaml
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any


def load_key_file(file_path: str) -> Dict[str, Any]:
    """Load and parse a key file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not load {file_path}: {e}")
        return {}


def calculate_rotation_status(key_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate rotation status for a key."""
    created_at_str = key_data.get('created_at')
    rotation_interval_days = key_data.get('rotation_interval_days', 365)
    
    if not created_at_str:
        return {
            "status": "error",
            "message": "No created_at date found",
            "days_remaining": None,
            "next_rotation_due": None
        }
    
    try:
        # Parse creation date
        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
        
        # Check for last rotation date
        lifecycle = key_data.get('lifecycle', {})
        last_rotated_str = lifecycle.get('last_rotated_at')
        
        if last_rotated_str:
            try:
                last_rotated = datetime.fromisoformat(last_rotated_str.replace('Z', '+00:00'))
                reference_date = last_rotated
            except ValueError:
                reference_date = created_at
        else:
            reference_date = created_at
        
        # Calculate next rotation due date
        next_rotation_due = reference_date + timedelta(days=rotation_interval_days)
        
        # Calculate days remaining
        now = datetime.now(next_rotation_due.tzinfo)
        days_remaining = (next_rotation_due - now).days
        
        # Determine status
        if days_remaining < 0:
            status = "overdue"
            message = f"{abs(days_remaining)} days overdue"
        elif days_remaining <= 7:
            status = "critical"
            message = f"{days_remaining} days remaining (critical)"
        elif days_remaining <= 30:
            status = "warning"
            message = f"{days_remaining} days remaining (warning)"
        else:
            status = "ok"
            message = f"{days_remaining} days remaining"
        
        return {
            "status": status,
            "message": message,
            "days_remaining": days_remaining,
            "next_rotation_due": next_rotation_due.isoformat(),
            "reference_date": reference_date.isoformat()
        }
    
    except ValueError as e:
        return {
            "status": "error",
            "message": f"Date parsing error: {e}",
            "days_remaining": None,
            "next_rotation_due": None
        }


def check_rotation_due(key_id: str = None, force: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """Check which keys are due for rotation."""
    inventory_dir = Path('inventory')
    if not inventory_dir.exists():
        print("Error: Inventory directory not found")
        return {"keys_to_rotate": [], "warning_keys": [], "errors": []}
    
    # Get all key files
    if key_id:
        key_files = [inventory_dir / f"{key_id}.yaml"]
        if not key_files[0].exists():
            key_files = [inventory_dir / f"{key_id}.yml"]
        if not key_files[0].exists():
            return {
                "keys_to_rotate": [],
                "warning_keys": [],
                "errors": [f"Key file not found for {key_id}"]
            }
    else:
        key_files = list(inventory_dir.glob('*.yaml')) + list(inventory_dir.glob('*.yml'))
    
    keys_to_rotate = []
    warning_keys = []
    errors = []
    
    for file_path in key_files:
        data = load_key_file(str(file_path))
        if not data:
            errors.append(f"Could not load {file_path}")
            continue
        
        # Skip non-active keys unless forced
        lifecycle = data.get('lifecycle', {})
        status = lifecycle.get('status', 'active')
        
        if status != 'active' and not force:
            continue
        
        # Check if auto-rotation is enabled
        operational = data.get('operational', {})
        auto_rotation = operational.get('auto_rotation_enabled', True)
        
        if not auto_rotation and not force:
            continue
        
        rotation_status = calculate_rotation_status(data)
        
        key_info = {
            "key_id": data.get('key_id'),
            "alias": data.get('alias'),
            "environment": data.get('environment'),
            "owner": data.get('owner'),
            "rotation_interval_days": data.get('rotation_interval_days'),
            "rotation_status": rotation_status,
            "file_path": str(file_path),
            "auto_rotation_enabled": auto_rotation,
            "status": status
        }
        
        if rotation_status["status"] in ["overdue", "critical"] or force:
            keys_to_rotate.append(key_info)
        elif rotation_status["status"] == "warning":
            warning_keys.append(key_info)
    
    return {
        "keys_to_rotate": keys_to_rotate,
        "warning_keys": warning_keys,
        "errors": errors
    }


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Check which keys are due for rotation')
    parser.add_argument('--key-id', help='Check specific key ID')
    parser.add_argument('--force', action='store_true', help='Force rotation check even for non-active keys')
    parser.add_argument('--output-json', action='store_true', help='Output results as JSON for GitHub Actions')
    parser.add_argument('--warning-days', type=int, default=30, help='Days before rotation to start warnings')
    parser.add_argument('--critical-days', type=int, default=7, help='Days before rotation for critical warnings')
    
    args = parser.parse_args()
    
    print(f"Checking rotation status...")
    if args.key_id:
        print(f"Specific key: {args.key_id}")
    if args.force:
        print("Force mode: checking all keys regardless of status")
    
    results = check_rotation_due(args.key_id, args.force)
    
    keys_to_rotate = results["keys_to_rotate"]
    warning_keys = results["warning_keys"]
    errors = results["errors"]
    
    # Print summary
    print(f"\nRotation Check Summary:")
    print(f"Keys due for rotation: {len(keys_to_rotate)}")
    print(f"Keys in warning period: {len(warning_keys)}")
    print(f"Errors: {len(errors)}")
    
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  ❌ {error}")
    
    if keys_to_rotate:
        print(f"\nKeys to rotate:")
        for key in keys_to_rotate:
            status = key["rotation_status"]["status"]
            message = key["rotation_status"]["message"]
            print(f"  🔄 {key['alias']} ({key['key_id']}) - {status}: {message}")
    
    if warning_keys:
        print(f"\nKeys approaching rotation:")
        for key in warning_keys:
            message = key["rotation_status"]["message"]
            print(f"  ⚠️ {key['alias']} ({key['key_id']}) - {message}")
    
    # Output for GitHub Actions
    if args.output_json:
        # Prepare data for GitHub Actions matrix
        matrix_keys = []
        for key in keys_to_rotate:
            matrix_keys.append({
                "key_id": key["key_id"],
                "alias": key["alias"],
                "environment": key["environment"],
                "owner": key["owner"]
            })
        
        warning_matrix = []
        for key in warning_keys:
            warning_matrix.append({
                "key_id": key["key_id"],
                "alias": key["alias"],
                "environment": key["environment"],
                "owner": key["owner"],
                "message": key["rotation_status"]["message"]
            })
        
        # Set GitHub Actions outputs
        print(f"::set-output name=keys::{json.dumps(matrix_keys)}")
        print(f"::set-output name=warning_keys::{json.dumps(warning_matrix)}")
        
        # Also write to files for debugging
        with open('keys_to_rotate.json', 'w') as f:
            json.dump(matrix_keys, f, indent=2)
        
        with open('warning_keys.json', 'w') as f:
            json.dump(warning_matrix, f, indent=2)
    
    # Exit with appropriate code
    if errors:
        sys.exit(2)  # Errors occurred
    elif keys_to_rotate:
        sys.exit(0)  # Keys found to rotate (success for GitHub Actions)
    else:
        sys.exit(0)  # No keys to rotate (success)


if __name__ == "__main__":
    main()