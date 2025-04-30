#!/usr/bin/env python3
"""
AWS Audit Manager SOC2 Assessment Creator

This script creates SOC2 assessments across multiple AWS accounts using AWS Audit Manager.
It can be used to standardize SOC2 assessments across your organization.

Requirements:
- boto3
- AWS CLI configured with appropriate permissions
- AWS Organizations setup with target accounts

Usage:
python create_soc2_assessment.py --accounts all|comma,separated,account,ids --role-name CrossAccountRole
"""

import argparse
import boto3
import json
import time
import sys
from datetime import datetime
from botocore.exceptions import ClientError

class SOC2AssessmentCreator:
    def __init__(self, accounts, role_name=None, region=None, profile=None):
        self.accounts = accounts
        self.role_name = role_name
        self.region = region or 'us-east-1'
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
                RoleSessionName='AuditManagerAssessment'
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
    
    def get_soc2_framework_id(self, audit_manager_client):
        """Get the SOC2 framework ID"""
        try:
            # List all frameworks
            frameworks = []
            paginator = audit_manager_client.get_paginator('list_assessment_frameworks')
            
            # First check standard frameworks
            for page in paginator.paginate(frameworkType='Standard'):
                for framework in page['frameworkMetadataList']:
                    if 'SOC 2' in framework['name']:
                        return framework['id']
            
            # Then check custom frameworks
            for page in paginator.paginate(frameworkType='Custom'):
                for framework in page['frameworkMetadataList']:
                    if 'SOC 2' in framework['name']:
                        return framework['id']
            
            print("SOC2 framework not found. Using default AWS SOC2 framework ARN.")
            # Default SOC2 framework ARN if not found
            return "arn:aws:auditmanager:us-east-1:068280491993:assessmentFramework/f5c5a0db-8a3e-4b1c-b1b0-a9a504a1ab8c"
            
        except ClientError as e:
            print(f"Error getting SOC2 framework: {e}")
            # Default SOC2 framework ARN if error
            return "arn:aws:auditmanager:us-east-1:068280491993:assessmentFramework/f5c5a0db-8a3e-4b1c-b1b0-a9a504a1ab8c"
    
    def create_assessment(self, account_id, account_name=None):
        """Create SOC2 assessment in target account"""
        session = self.assume_role(account_id)
        if not session:
            return False
        
        audit_manager_client = session.client('auditmanager', region_name=self.region)
        
        # Check if Audit Manager is enabled
        try:
            audit_manager_client.get_settings()
        except ClientError as e:
            if 'AccessDeniedException' in str(e):
                print(f"Account {account_id}: Access denied. Check IAM permissions.")
                return False
            elif 'ResourceNotFoundException' in str(e):
                print(f"Account {account_id}: Audit Manager is not enabled. Enabling...")
                try:
                    audit_manager_client.register_organization_admin_account(
                        adminAccountId=account_id
                    )
                    # Wait for service to be enabled
                    time.sleep(10)
                except ClientError as enable_error:
                    print(f"Account {account_id}: Failed to enable Audit Manager: {enable_error}")
                    return False
        
        # Get SOC2 framework ID
        framework_id = self.get_soc2_framework_id(audit_manager_client)
        
        # Create assessment name with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d")
        assessment_name = f"SOC2 Assessment - {account_name or account_id} - {timestamp}"
        
        # Get AWS services to include in assessment scope
        aws_services = [
            {"serviceName": "EC2"},
            {"serviceName": "S3"},
            {"serviceName": "IAM"},
            {"serviceName": "CloudTrail"},
            {"serviceName": "Config"},
            {"serviceName": "KMS"},
            {"serviceName": "CloudWatch"},
            {"serviceName": "GuardDuty"},
            {"serviceName": "SecurityHub"},
            {"serviceName": "Lambda"},
            {"serviceName": "RDS"}
        ]
        
        try:
            # Get current user/role for assessment owner
            caller_identity = self.sts_client.get_caller_identity()
            role_arn = caller_identity['Arn']
            
            # Create the assessment
            response = audit_manager_client.create_assessment(
                name=assessment_name,
                description=f"SOC2 compliance assessment for {account_name or account_id}",
                assessmentReportsDestination={
                    "destinationType": "S3",
                    "destination": f"s3://audit-manager-{account_id}-{self.region}"
                },
                scope={
                    "awsAccounts": [
                        {
                            "id": account_id,
                            "name": account_name or account_id
                        }
                    ],
                    "awsServices": aws_services
                },
                roles=[
                    {
                        "roleType": "PROCESS_OWNER",
                        "roleArn": role_arn
                    }
                ],
                frameworkId=framework_id
            )
            
            print(f"Account {account_id}: Created SOC2 assessment '{assessment_name}' with ID {response['assessment']['id']}")
            return True
            
        except ClientError as e:
            print(f"Account {account_id}: Error creating SOC2 assessment: {e}")
            return False
    
    def create_assessments(self):
        """Create SOC2 assessments across all target accounts"""
        if self.accounts == ['all']:
            accounts = self.get_all_accounts()
            print(f"Found {len(accounts)} accounts in the organization")
        else:
            accounts = [{'id': account_id, 'name': None} for account_id in self.accounts]
        
        success_count = 0
        failure_count = 0
        
        for account in accounts:
            print(f"\nProcessing account {account['id']} ({account['name'] or 'Unknown'})...")
            if self.create_assessment(account['id'], account['name']):
                success_count += 1
            else:
                failure_count += 1
        
        print(f"\nAssessment creation complete: {success_count} successful, {failure_count} failed")
        return success_count > 0

def main():
    parser = argparse.ArgumentParser(description='Create SOC2 assessments across multiple AWS accounts')
    parser.add_argument('--accounts', required=True, help='Comma-separated list of account IDs or "all" for all accounts')
    parser.add_argument('--role-name', help='Name of the IAM role to assume in target accounts')
    parser.add_argument('--region', default='us-east-1', help='AWS region for Audit Manager')
    parser.add_argument('--profile', help='AWS CLI profile to use instead of assuming a role')
    
    args = parser.parse_args()
    
    if not args.role_name and not args.profile:
        print("Error: Either --role-name or --profile must be specified")
        parser.print_help()
        sys.exit(1)
    
    target_accounts = args.accounts.split(',') if args.accounts != 'all' else ['all']
    
    creator = SOC2AssessmentCreator(
        accounts=target_accounts,
        role_name=args.role_name,
        region=args.region,
        profile=args.profile
    )
    
    success = creator.create_assessments()
    
    if success:
        print("\nSOC2 assessment creation completed successfully!")
        print("\nNext steps:")
        print("1. Log in to the AWS Management Console for each account")
        print("2. Navigate to AWS Audit Manager")
        print("3. Review the created SOC2 assessments")
        print("4. Begin collecting evidence and preparing for your audit")
    else:
        print("\nSOC2 assessment creation encountered issues. Please check the logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
