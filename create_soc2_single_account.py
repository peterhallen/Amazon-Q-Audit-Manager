#!/usr/bin/env python3
"""
AWS Audit Manager SOC2 Assessment Creator for Single Account

This script creates a SOC2 assessment in the current AWS account using AWS Audit Manager.

Requirements:
- boto3
- AWS CLI configured with appropriate permissions

Usage:
python create_soc2_single_account.py --profile PROFILE_NAME --region REGION
"""

import argparse
import boto3
import json
import time
import sys
from datetime import datetime
from botocore.exceptions import ClientError

class SOC2AssessmentCreator:
    def __init__(self, profile=None, region=None):
        self.region = region or 'us-east-1'
        
        # Initialize session
        if profile:
            print(f"Using AWS profile: {profile}")
            self.session = boto3.Session(profile_name=profile, region_name=self.region)
        else:
            print("Using default AWS credentials")
            self.session = boto3.Session(region_name=self.region)
        
        # Verify identity
        try:
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']
            self.role_arn = identity['Arn']
            print(f"Using AWS identity: {self.role_arn} in account {self.account_id}")
        except Exception as e:
            print(f"Error verifying identity: {e}")
            sys.exit(1)
        
        # Initialize clients
        self.audit_manager_client = self.session.client('auditmanager', region_name=self.region)
    
    def get_soc2_framework_id(self):
        """Get the SOC2 framework ID"""
        try:
            # List all frameworks
            frameworks = []
            
            # First check standard frameworks
            response = self.audit_manager_client.list_assessment_frameworks(frameworkType='Standard')
            for framework in response.get('frameworkMetadataList', []):
                if 'SOC 2' in framework['name'] or 'SOC2' in framework['name'] or 'Service Organizations Controls' in framework['name']:
                    print(f"Found SOC2 framework: {framework['name']} ({framework['id']})")
                    return framework['id']
            
            # Then check custom frameworks
            response = self.audit_manager_client.list_assessment_frameworks(frameworkType='Custom')
            for framework in response.get('frameworkMetadataList', []):
                if 'SOC 2' in framework['name'] or 'SOC2' in framework['name'] or 'Service Organizations Controls' in framework['name']:
                    print(f"Found custom SOC2 framework: {framework['name']} ({framework['id']})")
                    return framework['id']
            
            print("SOC2 framework not found. Using default SOC2 framework ID.")
            # Default SOC2 framework ID if not found
            return "a3b2dc50-59c3-401d-8c0b-2fc123175d2d"
            
        except ClientError as e:
            print(f"Error getting SOC2 framework: {e}")
            # Default SOC2 framework ID if error
            return "a3b2dc50-59c3-401d-8c0b-2fc123175d2d"
    
    def check_audit_manager_enabled(self):
        """Check if Audit Manager is enabled"""
        try:
            self.audit_manager_client.get_settings(attribute='ALL')
            return True
        except ClientError as e:
            if 'ResourceNotFoundException' in str(e):
                print("Audit Manager is not enabled. Please run deploy_single_account.py first.")
                return False
            elif 'AccessDeniedException' in str(e):
                print("Access denied. Check IAM permissions.")
                return False
            else:
                print(f"Error checking Audit Manager status: {e}")
                return False
    
    def create_assessment(self):
        """Create SOC2 assessment"""
        # Check if Audit Manager is enabled
        if not self.check_audit_manager_enabled():
            return False
        
        # Get SOC2 framework ID
        framework_id = self.get_soc2_framework_id()
        
        # Create assessment name with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d")
        assessment_name = f"SOC2 Assessment - {timestamp}"
        
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
            # Get S3 bucket for assessment reports
            try:
                settings = self.audit_manager_client.get_settings(attribute='ALL')
                default_destination = settings.get('defaultAssessmentReportsDestination', {})
                destination = default_destination.get('destination', f"s3://audit-manager-reports-{self.account_id}-{self.region}")
            except ClientError:
                destination = f"s3://audit-manager-reports-{self.account_id}-{self.region}"
            
            # Create the assessment
            print(f"Creating SOC2 assessment: {assessment_name}")
            response = self.audit_manager_client.create_assessment(
                name=assessment_name,
                description=f"SOC2 compliance assessment for account {self.account_id}",
                assessmentReportsDestination={
                    "destinationType": "S3",
                    "destination": destination
                },
                scope={
                    "awsAccounts": [
                        {
                            "id": self.account_id
                        }
                    ],
                    "awsServices": aws_services
                },
                roles=[
                    {
                        "roleType": "PROCESS_OWNER",
                        "roleArn": self.role_arn
                    }
                ],
                frameworkId=framework_id
            )
            
            print(f"Response: {response}")
            assessment_id = response.get('assessment', {}).get('id')
            if assessment_id:
                print(f"Created SOC2 assessment '{assessment_name}' with ID {assessment_id}")
            else:
                print(f"Assessment created but couldn't get ID. Check AWS Console.")
            
            print("\nNext steps:")
            print("1. Log in to the AWS Management Console")
            print("2. Navigate to AWS Audit Manager")
            print("3. Open the created SOC2 assessment")
            print("4. Begin collecting evidence")
            
            return True
            
        except ClientError as e:
            print(f"Error creating SOC2 assessment: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Create SOC2 assessment in a single AWS account')
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region for Audit Manager')
    
    args = parser.parse_args()
    
    creator = SOC2AssessmentCreator(
        profile=args.profile,
        region=args.region
    )
    
    success = creator.create_assessment()
    
    if not success:
        print("\nSOC2 assessment creation encountered issues. Please check the logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
