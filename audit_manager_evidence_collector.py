#!/usr/bin/env python3
"""
AWS Audit Manager Evidence Collector

This script automates the collection of evidence for AWS Audit Manager assessments
across multiple AWS accounts. It can be scheduled to run periodically to ensure
continuous evidence collection for compliance audits.

Requirements:
- boto3
- AWS CLI configured with appropriate permissions
- AWS Organizations setup with target accounts

Usage:
python audit_manager_evidence_collector.py --accounts all|comma,separated,account,ids --role-name CrossAccountRole
"""

import argparse
import boto3
import json
import time
import sys
import uuid
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

class AuditManagerEvidenceCollector:
    def __init__(self, accounts, role_name=None, region=None, assessment_id=None, profile=None):
        self.accounts = accounts
        self.role_name = role_name
        self.region = region or 'us-east-1'
        self.assessment_id = assessment_id
        self.profile = profile
        
        # Initialize session with profile if provided
        if profile:
            print(f"Using AWS profile: {profile}")
            self.session = boto3.Session(profile_name=profile, region_name=self.region)
        else:
            self.session = boto3.Session(region_name=self.region)
            
        # Verify identity
        try:
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            print(f"Using AWS identity: {identity['Arn']}")
        except Exception as e:
            print(f"Warning: Could not verify identity: {e}")
            
        self.organizations_client = self.session.client('organizations')
        self.sts_client = self.session.client('sts')
        
    def get_all_accounts(self):
        """Get all accounts in the organization"""
        accounts = []
        paginator = self.organizations_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append({
                        'id': account['Id'],
                        'name': account['Name']
                    })
        
        return accounts
    
    def assume_role(self, account_id):
        """Assume role in target account"""
        # If no role name is provided, use the current session
        if not self.role_name:
            print(f"Using current credentials for account {account_id}")
            return self.session
            
        role_arn = f"arn:aws:iam::{account_id}:role/{self.role_name}"
        
        try:
            print(f"Attempting to assume role: {role_arn}")
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='AuditManagerEvidence'
            )
            
            credentials = response['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=self.region
            )
        except ClientError as e:
            print(f"Error assuming role in account {account_id}: {e}")
            return None
    
    def get_active_assessments(self, audit_manager_client):
        """Get all active assessments in the account"""
        assessments = []
        
        try:
            response = audit_manager_client.list_assessments(status='ACTIVE')
            assessments.extend(response.get('assessmentMetadata', []))
            
            return assessments
        except ClientError as e:
            print(f"Error getting assessments: {e}")
            return []
    
    def get_control_sets(self, audit_manager_client, assessment_id):
        """Get all control sets for an assessment"""
        control_sets = []
        
        try:
            response = audit_manager_client.list_assessment_control_sets(assessmentId=assessment_id)
            control_sets.extend(response.get('controlSets', []))
            
            return control_sets
        except ClientError as e:
            print(f"Error getting control sets for assessment {assessment_id}: {e}")
            return []
    
    def get_controls(self, audit_manager_client, assessment_id, control_set_id):
        """Get all controls in a control set"""
        controls = []
        
        try:
            response = audit_manager_client.list_assessment_controls(
                assessmentId=assessment_id,
                controlSetId=control_set_id
            )
            controls.extend(response.get('controls', []))
            
            return controls
        except ClientError as e:
            print(f"Error getting controls for assessment {assessment_id}, control set {control_set_id}: {e}")
            return []
    
    def collect_manual_evidence(self, audit_manager_client, assessment_id, control_id):
        """Collect manual evidence for a control"""
        try:
            # Get the control set ID for this control
            assessment_details = audit_manager_client.get_assessment(assessmentId=assessment_id)
            control_set_id = None
            
            # Find the control set ID that contains this control
            for control_set in assessment_details['assessment']['framework']['controlSets']:
                for control in control_set['controls']:
                    if control['id'] == control_id:
                        control_set_id = control_set['id']
                        break
                if control_set_id:
                    break
            
            if not control_set_id:
                print(f"Could not find control set ID for control {control_id}")
                return False
            
            # Example of uploading a manual evidence
            current_date = datetime.now().strftime('%Y-%m-%d')
            evidence_text = f"This evidence was automatically collected by the audit_manager_evidence_collector.py script on {current_date}."
            
            print(f"Adding manual evidence for control {control_id} in control set {control_set_id}")
            response = audit_manager_client.batch_import_evidence_to_assessment_control(
                assessmentId=assessment_id,
                controlId=control_id,
                controlSetId=control_set_id,
                manualEvidence=[
                    {
                        "textResponse": evidence_text
                    }
                ]
            )
            
            print(f"Evidence added successfully")
            return True
        except ClientError as e:
            print(f"Error collecting manual evidence for control {control_id}: {e}")
            return False
    
    def start_evidence_collection(self, audit_manager_client, assessment_id, control_set_id):
        """Start automated evidence collection for a control set"""
        try:
            response = audit_manager_client.start_assessment_framework_share(
                assessmentId=assessment_id,
                controlSetId=control_set_id
            )
            
            print(f"Started evidence collection for control set {control_set_id}")
            return True
        except ClientError as e:
            print(f"Error starting evidence collection for control set {control_set_id}: {e}")
            return False
    
    def process_account(self, account_id, account_name=None):
        """Process an account to collect evidence"""
        print(f"\nProcessing account {account_id} ({account_name or 'Unknown'})...")
        
        session = self.assume_role(account_id)
        if not session:
            return False
        
        audit_manager_client = session.client('auditmanager', region_name=self.region)
        
        # Check if Audit Manager is enabled
        try:
            audit_manager_client.get_settings(attribute='ALL')
        except ClientError as e:
            print(f"Account {account_id}: Audit Manager is not properly configured: {e}")
            return False
        
        # Get assessments
        if self.assessment_id:
            try:
                assessment = audit_manager_client.get_assessment(assessmentId=self.assessment_id)
                assessments = [assessment['assessment']]
            except ClientError as e:
                print(f"Account {account_id}: Error getting assessment {self.assessment_id}: {e}")
                return False
        else:
            assessments = self.get_active_assessments(audit_manager_client)
            if not assessments:
                print(f"Account {account_id}: No active assessments found")
                return False
        
        success = False
        
        # Process each assessment
        for assessment in assessments:
            assessment_id = assessment['metadata']['id']
            assessment_name = assessment['metadata']['name']
            print(f"Account {account_id}: Processing assessment '{assessment_name}' ({assessment_id})")
            
            # Get control sets from the assessment
            try:
                assessment_details = audit_manager_client.get_assessment(assessmentId=assessment_id)
                control_sets = assessment_details['assessment']['framework']['controlSets']
                
                if not control_sets:
                    print(f"Account {account_id}: No control sets found for assessment {assessment_id}")
                    continue
                
                # Process each control set
                for control_set in control_sets:
                    control_set_id = control_set['id']
                    control_set_name = control_set['description'] or control_set['id']
                    print(f"Account {account_id}: Processing control set '{control_set_name}' ({control_set_id})")
                    
                    # Process each control
                    for control in control_set['controls']:
                        control_id = control['id']
                        control_name = control['name']
                        
                        # Collect manual evidence for demonstration purposes
                        if self.collect_manual_evidence(audit_manager_client, assessment_id, control_id):
                            print(f"Account {account_id}: Collected evidence for control '{control_name}' ({control_id})")
                            success = True
                
            except ClientError as e:
                print(f"Account {account_id}: Error processing assessment: {e}")
                continue
            
        return success
    
    def collect_evidence(self):
        """Collect evidence across all target accounts"""
        if self.accounts == ['all']:
            accounts = self.get_all_accounts()
            print(f"Found {len(accounts)} accounts in the organization")
        else:
            accounts = [{'id': account_id, 'name': None} for account_id in self.accounts]
        
        success_count = 0
        failure_count = 0
        
        for account in accounts:
            if self.process_account(account['id'], account['name']):
                success_count += 1
            else:
                failure_count += 1
        
        print(f"\nEvidence collection complete: {success_count} successful, {failure_count} failed")
        return success_count > 0

def main():
    parser = argparse.ArgumentParser(description='Collect evidence for AWS Audit Manager assessments')
    parser.add_argument('--accounts', required=True, help='Comma-separated list of account IDs or "all" for all accounts')
    parser.add_argument('--role-name', help='Name of the IAM role to assume in target accounts')
    parser.add_argument('--region', default='us-east-1', help='AWS region for Audit Manager')
    parser.add_argument('--assessment-id', help='Specific assessment ID to collect evidence for (optional)')
    parser.add_argument('--profile', help='AWS CLI profile to use instead of assuming a role')
    
    args = parser.parse_args()
    
    if not args.role_name and not args.profile:
        print("Error: Either --role-name or --profile must be specified")
        parser.print_help()
        sys.exit(1)
    
    target_accounts = args.accounts.split(',') if args.accounts != 'all' else ['all']
    
    collector = AuditManagerEvidenceCollector(
        accounts=target_accounts,
        role_name=args.role_name,
        region=args.region,
        assessment_id=args.assessment_id,
        profile=args.profile
    )
    
    success = collector.collect_evidence()
    
    if success:
        print("\nEvidence collection completed successfully!")
        print("\nNext steps:")
        print("1. Log in to the AWS Management Console for each account")
        print("2. Navigate to AWS Audit Manager")
        print("3. Review the collected evidence")
        print("4. Generate assessment reports as needed")
    else:
        print("\nEvidence collection encountered issues. Please check the logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
