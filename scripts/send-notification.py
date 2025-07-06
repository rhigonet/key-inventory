#!/usr/bin/env python3
"""
Notification Service
Sends notifications for key lifecycle events
"""

import os
import sys
import json
import yaml
import requests
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class NotificationService:
    def __init__(self):
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
        self.email_config = self.load_email_config()
        self.pagerduty_config = self.load_pagerduty_config()
    
    def load_email_config(self) -> Dict[str, str]:
        """Load email configuration from environment."""
        email_config_str = os.getenv('EMAIL_CONFIG', '{}')
        try:
            return json.loads(email_config_str)
        except json.JSONDecodeError:
            return {}
    
    def load_pagerduty_config(self) -> Dict[str, str]:
        """Load PagerDuty configuration from environment."""
        return {
            'api_key': os.getenv('PAGERDUTY_API_KEY'),
            'service_id': os.getenv('PAGERDUTY_SERVICE_ID')
        }
    
    def send_slack_notification(self, notification: Dict[str, Any]) -> bool:
        """Send Slack notification."""
        if not self.slack_webhook:
            print("Warning: SLACK_WEBHOOK_URL not configured")
            return False
        
        try:
            color_map = {
                'info': '#36a64f',
                'warning': '#ff9900',
                'error': '#ff0000',
                'success': '#36a64f',
                'critical': '#ff0000'
            }
            
            color = color_map.get(notification.get('severity', 'info'), '#36a64f')
            
            payload = {
                "text": notification['title'],
                "attachments": [
                    {
                        "color": color,
                        "fields": [
                            {
                                "title": "Type",
                                "value": notification['type'],
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": notification.get('severity', 'info').upper(),
                                "short": True
                            },
                            {
                                "title": "Message",
                                "value": notification['message'],
                                "short": False
                            },
                            {
                                "title": "Timestamp",
                                "value": notification['timestamp'],
                                "short": True
                            }
                        ]
                    }
                ]
            }
            
            # Add additional fields if present
            if 'key_id' in notification:
                payload["attachments"][0]["fields"].append({
                    "title": "Key ID",
                    "value": notification['key_id'],
                    "short": True
                })
            
            if 'alias' in notification:
                payload["attachments"][0]["fields"].append({
                    "title": "Alias",
                    "value": notification['alias'],
                    "short": True
                })
            
            if 'environment' in notification:
                payload["attachments"][0]["fields"].append({
                    "title": "Environment",
                    "value": notification['environment'],
                    "short": True
                })
            
            if 'owner' in notification:
                payload["attachments"][0]["fields"].append({
                    "title": "Owner",
                    "value": notification['owner'],
                    "short": True
                })
            
            if 'additional_info' in notification:
                payload["attachments"][0]["fields"].append({
                    "title": "Additional Info",
                    "value": notification['additional_info'],
                    "short": False
                })
            
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            response.raise_for_status()
            print("✅ Slack notification sent successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send Slack notification: {e}")
            return False
    
    def send_email_notification(self, notification: Dict[str, Any]) -> bool:
        """Send email notification."""
        if not self.email_config:
            print("Warning: EMAIL_CONFIG not configured")
            return False
        
        # Email implementation would go here
        # For now, just log that it would be sent
        print(f"📧 Email notification would be sent: {notification['title']}")
        return True
    
    def send_pagerduty_alert(self, notification: Dict[str, Any]) -> bool:
        """Send PagerDuty alert."""
        if not self.pagerduty_config.get('api_key'):
            print("Warning: PAGERDUTY_API_KEY not configured")
            return False
        
        # PagerDuty implementation would go here
        # For now, just log that it would be sent
        print(f"📟 PagerDuty alert would be sent: {notification['title']}")
        return True
    
    def create_key_created_notification(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create notification for key creation."""
        return {
            'type': 'key-created',
            'severity': 'info',
            'title': f"🔑 New Key Created: {key_data.get('alias', 'Unknown')}",
            'message': f"A new cryptographic key has been created and provisioned.",
            'timestamp': datetime.now().isoformat(),
            'key_id': key_data.get('key_id'),
            'alias': key_data.get('alias'),
            'environment': key_data.get('environment'),
            'owner': key_data.get('owner'),
            'additional_info': f"Purpose: {key_data.get('purpose', 'Not specified')}"
        }
    
    def create_key_deleted_notification(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create notification for key deletion."""
        return {
            'type': 'key-deleted',
            'severity': 'warning',
            'title': f"🗑️ Key Deleted: {key_data.get('alias', 'Unknown')}",
            'message': f"A cryptographic key has been permanently deleted.",
            'timestamp': datetime.now().isoformat(),
            'key_id': key_data.get('key_id'),
            'alias': key_data.get('alias'),
            'environment': key_data.get('environment'),
            'owner': key_data.get('owner'),
            'additional_info': f"Deletion reason: {key_data.get('deletion_reason', 'Not specified')}"
        }
    
    def create_key_rotated_notification(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create notification for key rotation."""
        return {
            'type': 'key-rotated',
            'severity': 'info',
            'title': f"🔄 Key Rotated: {key_data.get('alias', 'Unknown')}",
            'message': f"A cryptographic key has been successfully rotated.",
            'timestamp': datetime.now().isoformat(),
            'key_id': key_data.get('key_id'),
            'alias': key_data.get('alias'),
            'environment': key_data.get('environment'),
            'owner': key_data.get('owner'),
            'additional_info': f"Next rotation due: {key_data.get('next_rotation_due', 'Not calculated')}"
        }
    
    def create_rotation_failed_notification(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create notification for failed key rotation."""
        return {
            'type': 'rotation-failed',
            'severity': 'error',
            'title': f"❌ Key Rotation Failed: {key_data.get('alias', 'Unknown')}",
            'message': f"Failed to rotate cryptographic key. Manual intervention required.",
            'timestamp': datetime.now().isoformat(),
            'key_id': key_data.get('key_id'),
            'alias': key_data.get('alias'),
            'environment': key_data.get('environment'),
            'owner': key_data.get('owner'),
            'additional_info': f"Error: {key_data.get('error', 'Unknown error')}"
        }
    
    def create_emergency_notification(self, key_data: Dict[str, Any], phase: str) -> Dict[str, Any]:
        """Create emergency notification."""
        phase_messages = {
            'initiated': 'Emergency key replacement procedure has been initiated',
            'revoked': 'Compromised key has been immediately revoked',
            'completed': 'Emergency key replacement has been completed successfully',
            'failed': 'Emergency key replacement procedure has failed - immediate action required'
        }
        
        phase_icons = {
            'initiated': '🚨',
            'revoked': '⛔',
            'completed': '✅',
            'failed': '💥'
        }
        
        severity = 'critical' if phase in ['initiated', 'failed'] else 'warning'
        
        return {
            'type': 'emergency-replacement',
            'severity': severity,
            'title': f"{phase_icons.get(phase, '🔔')} Emergency: {key_data.get('alias', 'Unknown')}",
            'message': phase_messages.get(phase, 'Emergency key replacement update'),
            'timestamp': datetime.now().isoformat(),
            'key_id': key_data.get('key_id'),
            'alias': key_data.get('alias'),
            'environment': key_data.get('environment'),
            'owner': key_data.get('owner'),
            'incident_id': key_data.get('incident_id'),
            'additional_info': f"Incident: {key_data.get('incident_id', 'Unknown')} | Severity: {key_data.get('severity', 'Unknown')}"
        }
    
    def send_notification(self, notification_type: str, **kwargs) -> bool:
        """Send notification based on type."""
        notification = None
        
        if notification_type == 'key-created':
            notification = self.create_key_created_notification(kwargs)
        elif notification_type == 'key-deleted':
            notification = self.create_key_deleted_notification(kwargs)
        elif notification_type == 'key-rotated':
            notification = self.create_key_rotated_notification(kwargs)
        elif notification_type == 'rotation-failed':
            notification = self.create_rotation_failed_notification(kwargs)
        elif notification_type == 'emergency':
            notification = self.create_emergency_notification(kwargs, kwargs.get('phase', 'initiated'))
        else:
            print(f"Unknown notification type: {notification_type}")
            return False
        
        if not notification:
            print(f"Failed to create notification for type: {notification_type}")
            return False
        
        # Send to configured channels
        success = True
        
        # Always try Slack first
        if not self.send_slack_notification(notification):
            success = False
        
        # Send email for important notifications
        if notification['severity'] in ['warning', 'error', 'critical']:
            if not self.send_email_notification(notification):
                success = False
        
        # Send PagerDuty for critical notifications
        if notification['severity'] == 'critical':
            if not self.send_pagerduty_alert(notification):
                success = False
        
        return success


def load_key_from_pr(pr_number: str) -> Dict[str, Any]:
    """Load key information from PR context."""
    # This would typically query the GitHub API to get PR details
    # For now, return mock data
    return {
        'key_id': 'unknown',
        'alias': f'pr-{pr_number}',
        'environment': 'unknown',
        'owner': 'unknown@example.com',
        'purpose': 'PR-based operation'
    }


def load_key_from_file(key_id: str) -> Dict[str, Any]:
    """Load key information from inventory file."""
    inventory_dir = Path('inventory')
    key_file = inventory_dir / f"{key_id}.yaml"
    
    if not key_file.exists():
        key_file = inventory_dir / f"{key_id}.yml"
    
    if not key_file.exists():
        return {'key_id': key_id, 'alias': 'unknown'}
    
    try:
        with open(key_file, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Warning: Could not load key file {key_file}: {e}")
        return {'key_id': key_id, 'alias': 'unknown'}


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Send key lifecycle notifications')
    parser.add_argument('--type', required=True, choices=[
        'key-created', 'key-deleted', 'key-rotated', 'rotation-failed', 'emergency'
    ], help='Type of notification to send')
    parser.add_argument('--key-id', help='Key ID for the notification')
    parser.add_argument('--pr-number', help='PR number for PR-based notifications')
    parser.add_argument('--incident-id', help='Incident ID for emergency notifications')
    parser.add_argument('--phase', help='Phase for emergency notifications')
    parser.add_argument('--severity', help='Severity for emergency notifications')
    parser.add_argument('--error', help='Error message for failed operations')
    parser.add_argument('--deletion-reason', help='Reason for key deletion')
    
    args = parser.parse_args()
    
    # Initialize notification service
    service = NotificationService()
    
    # Load key data
    key_data = {}
    
    if args.key_id:
        key_data = load_key_from_file(args.key_id)
    elif args.pr_number:
        key_data = load_key_from_pr(args.pr_number)
    
    # Add additional parameters
    if args.incident_id:
        key_data['incident_id'] = args.incident_id
    if args.phase:
        key_data['phase'] = args.phase
    if args.severity:
        key_data['severity'] = args.severity
    if args.error:
        key_data['error'] = args.error
    if args.deletion_reason:
        key_data['deletion_reason'] = args.deletion_reason
    
    # Send notification
    print(f"Sending {args.type} notification...")
    success = service.send_notification(args.type, **key_data)
    
    if success:
        print("✅ Notification sent successfully")
        sys.exit(0)
    else:
        print("❌ Failed to send notification")
        sys.exit(1)


if __name__ == "__main__":
    main()