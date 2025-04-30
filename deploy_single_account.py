#!/usr/bin/env python3
"""
AWS Audit Manager Single Account Deployment Script

This script deploys AWS Audit Manager in a single AWS account without requiring
AWS Organizations or CloudFormation StackSets.

Requirements:
- boto3
- AWS CLI configured with appropriate permissions

Usage:
python deploy_single_account.py --profile PROFILE_NAME --region REGION
"""

import argparse
import boto3
import json
import time
import sys
from botocore.exceptions import ClientError

class SingleAccountDeployer:
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
            print(f"Using AWS identity: {identity['Arn']} in account {self.account_id}")
        except Exception as e:
            print(f"Error verifying identity: {e}")
            sys.exit(1)
        
        # Initialize clients
        self.cloudformation_client = self.session.client('cloudformation')
        self.audit_manager_client = self.session.client('auditmanager', region_name=self.region)
    
    def create_audit_manager_role_template(self):
        """Create CloudFormation template for Audit Manager IAM role"""
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AWS Audit Manager IAM Role",
            "Resources": {
                "AuditManagerRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "AuditManagerServiceRole",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "auditmanager.amazonaws.com"
                                    },
                                    "Action": "sts:AssumeRole"
                                }
                            ]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/aws-service-role/AWSAuditManagerServiceRolePolicy"
                        ],
                        "Path": "/service-role/"
                    }
                }
            },
            "Outputs": {
                "AuditManagerRoleArn": {
                    "Description": "ARN of the Audit Manager Service Role",
                    "Value": {"Fn::GetAtt": ["AuditManagerRole", "Arn"]}
                }
            }
        }
        
        return json.dumps(template)
    
    def create_audit_manager_config_template(self):
        """Create CloudFormation template for Audit Manager configuration"""
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AWS Audit Manager Configuration",
            "Resources": {
                "AuditManagerAdminRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "AuditManagerAdminRole",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "auditmanager.amazonaws.com"
                                    },
                                    "Action": "sts:AssumeRole"
                                }
                            ]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AWSAuditManagerAdministratorAccess"
                        ]
                    }
                },
                "S3ReportBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {"Fn::Join": ["-", ["audit-manager-reports", {"Ref": "AWS::AccountId"}, {"Ref": "AWS::Region"}]]},
                        "BucketEncryption": {
                            "ServerSideEncryptionConfiguration": [
                                {
                                    "ServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    }
                                }
                            ]
                        },
                        "VersioningConfiguration": {
                            "Status": "Enabled"
                        }
                    }
                },
                "S3BucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "S3ReportBucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AuditManagerBucketPermissions",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "auditmanager.amazonaws.com"
                                    },
                                    "Action": [
                                        "s3:PutObject",
                                        "s3:GetObject",
                                        "s3:ListBucket"
                                    ],
                                    "Resource": [
                                        {"Fn::Join": ["", ["arn:aws:s3:::", {"Ref": "S3ReportBucket"}]]},
                                        {"Fn::Join": ["", ["arn:aws:s3:::", {"Ref": "S3ReportBucket"}, "/*"]]}
                                    ]
                                }
                            ]
                        }
                    }
                }
            },
            "Outputs": {
                "ReportBucketName": {
                    "Description": "Name of the S3 bucket for Audit Manager reports",
                    "Value": {"Ref": "S3ReportBucket"}
                },
                "AuditManagerAdminRoleArn": {
                    "Description": "ARN of the Audit Manager Admin Role",
                    "Value": {"Fn::GetAtt": ["AuditManagerAdminRole", "Arn"]}
                }
            }
        }
        
        return json.dumps(template)
    
    def deploy_stack(self, stack_name, template):
        """Deploy a CloudFormation stack"""
        try:
            # Check if stack exists
            try:
                self.cloudformation_client.describe_stacks(StackName=stack_name)
                stack_exists = True
            except ClientError:
                stack_exists = False
            
            if stack_exists:
                print(f"Updating stack: {stack_name}")
                response = self.cloudformation_client.update_stack(
                    StackName=stack_name,
                    TemplateBody=template,
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
                waiter = self.cloudformation_client.get_waiter('stack_update_complete')
            else:
                print(f"Creating stack: {stack_name}")
                response = self.cloudformation_client.create_stack(
                    StackName=stack_name,
                    TemplateBody=template,
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
                waiter = self.cloudformation_client.get_waiter('stack_create_complete')
            
            print(f"Waiting for stack {stack_name} to complete...")
            waiter.wait(StackName=stack_name)
            print(f"Stack {stack_name} completed successfully")
            
            return True
        except ClientError as e:
            print(f"Error deploying stack {stack_name}: {e}")
            return False
    
    def enable_audit_manager(self):
        """Enable AWS Audit Manager"""
        try:
            # Check if Audit Manager is already enabled
            try:
                self.audit_manager_client.get_settings()
                print("Audit Manager is already enabled")
                return True
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    print(f"Error checking Audit Manager status: {e}")
                    return False
            
            # Get the S3 bucket name from the CloudFormation stack
            try:
                response = self.cloudformation_client.describe_stacks(StackName='AuditManagerConfiguration')
                outputs = response['Stacks'][0]['Outputs']
                bucket_name = next((output['OutputValue'] for output in outputs if output['OutputKey'] == 'ReportBucketName'), None)
                admin_role_arn = next((output['OutputValue'] for output in outputs if output['OutputKey'] == 'AuditManagerAdminRoleArn'), None)
            except ClientError as e:
                print(f"Error getting stack outputs: {e}")
                bucket_name = f"audit-manager-reports-{self.account_id}-{self.region}"
                admin_role_arn = f"arn:aws:iam::{self.account_id}:role/AuditManagerAdminRole"
            
            # Enable Audit Manager
            print("Enabling AWS Audit Manager...")
            self.audit_manager_client.register_account(
                kmsKey='',  # Optional, using default KMS key
                delegatedAdminAccount=self.account_id
            )
            
            # Configure Audit Manager settings
            print("Configuring AWS Audit Manager settings...")
            self.audit_manager_client.update_settings(
                defaultAssessmentReportsDestination={
                    'destinationType': 'S3',
                    'destination': f"s3://{bucket_name}"
                },
                defaultProcessOwners=[
                    {
                        'roleArn': admin_role_arn
                    }
                ]
            )
            
            print("AWS Audit Manager enabled and configured successfully")
            return True
        except ClientError as e:
            print(f"Error enabling Audit Manager: {e}")
            return False
    
    def deploy_audit_manager(self):
        """Deploy AWS Audit Manager in a single account"""
        print(f"Starting AWS Audit Manager deployment in account {self.account_id}")
        
        # Step 1: Deploy IAM role for Audit Manager
        role_template = self.create_audit_manager_role_template()
        role_deployment = self.deploy_stack('AuditManagerServiceRole', role_template)
        
        if not role_deployment:
            print("Failed to deploy Audit Manager service role")
            return False
        
        # Step 2: Deploy Audit Manager configuration
        config_template = self.create_audit_manager_config_template()
        config_deployment = self.deploy_stack('AuditManagerConfiguration', config_template)
        
        if not config_deployment:
            print("Failed to deploy Audit Manager configuration")
            return False
        
        # Step 3: Enable and configure Audit Manager
        audit_manager_setup = self.enable_audit_manager()
        if not audit_manager_setup:
            print("Failed to enable Audit Manager")
            return False
        
        print("AWS Audit Manager deployment completed successfully")
        return True

def main():
    parser = argparse.ArgumentParser(description='Deploy AWS Audit Manager in a single account')
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region for deployment')
    
    args = parser.parse_args()
    
    deployer = SingleAccountDeployer(
        profile=args.profile,
        region=args.region
    )
    
    success = deployer.deploy_audit_manager()
    
    if success:
        print("\nAudit Manager deployment completed successfully!")
        print("\nNext steps:")
        print("1. Log in to the AWS Management Console")
        print("2. Navigate to AWS Audit Manager")
        print("3. Create assessments for your compliance frameworks")
        print("4. Begin collecting evidence")
    else:
        print("\nAudit Manager deployment encountered issues. Please check the logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
