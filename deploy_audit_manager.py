#!/usr/bin/env python3
"""
AWS Audit Manager Multi-Account Deployment Script

This script helps deploy and configure AWS Audit Manager across multiple AWS accounts
using AWS Organizations and CloudFormation StackSets.

Requirements:
- boto3
- AWS CLI configured with appropriate permissions
- AWS Organizations setup with target accounts

Usage:
python deploy_audit_manager.py --management-account-role YourManagementRole --target-accounts all|comma,separated,account,ids
"""

import argparse
import boto3
import json
import time
import sys
from botocore.exceptions import ClientError

class AuditManagerDeployer:
    def __init__(self, management_role_arn=None, target_accounts=None, region=None, profile=None):
        self.management_role_arn = management_role_arn
        self.target_accounts = target_accounts
        self.region = region or 'us-east-1'
        self.profile = profile
        
        # Initialize session
        try:
            if management_role_arn:
                print(f"Attempting to assume role: {management_role_arn}")
                sts_client = boto3.client('sts')
                assumed_role = sts_client.assume_role(
                    RoleArn=management_role_arn,
                    RoleSessionName='AuditManagerDeployment'
                )
                credentials = assumed_role['Credentials']
                
                self.session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=self.region
                )
                print("Successfully assumed role")
            elif profile:
                print(f"Using AWS profile: {profile}")
                self.session = boto3.Session(profile_name=profile, region_name=self.region)
            else:
                print("Using default AWS credentials")
                self.session = boto3.Session(region_name=self.region)
            
            # Verify credentials
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            print(f"Using AWS identity: {identity['Arn']}")
            
        except Exception as e:
            print(f"Error initializing AWS session: {e}")
            print("Falling back to default credentials")
            self.session = boto3.Session(region_name=self.region)
        
        # Initialize clients
        self.organizations_client = self.session.client('organizations')
        self.cloudformation_client = self.session.client('cloudformation')
        self.sts_client = self.session.client('sts')
        
    def get_all_accounts(self):
        """Get all accounts in the organization"""
        accounts = []
        paginator = self.organizations_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append(account['Id'])
        
        return accounts
    
    def create_audit_manager_role(self):
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
    
    def create_audit_manager_config(self):
        """Create CloudFormation template for Audit Manager configuration"""
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AWS Audit Manager Configuration",
            "Parameters": {
                "KmsKeyArn": {
                    "Type": "String",
                    "Description": "ARN of KMS key for Audit Manager encryption (optional)",
                    "Default": ""
                },
                "SNSTopicArn": {
                    "Type": "String",
                    "Description": "ARN of SNS topic for Audit Manager notifications (optional)",
                    "Default": ""
                }
            },
            "Resources": {
                "AuditManagerSettings": {
                    "Type": "AWS::AuditManager::Settings",
                    "Properties": {
                        "DefaultAssessmentReportsDestination": {
                            "Destination": {"Ref": "S3ReportBucket"},
                            "DestinationType": "S3"
                        },
                        "DefaultProcessOwners": [
                            {
                                "RoleArn": {"Fn::GetAtt": ["AuditManagerAdminRole", "Arn"]}
                            }
                        ],
                        "KmsKey": {"Ref": "KmsKeyArn"}
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
    
    def create_soc2_assessment_template(self):
        """Create CloudFormation template for SOC2 assessment"""
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AWS Audit Manager SOC2 Assessment",
            "Resources": {
                "SOC2Assessment": {
                    "Type": "AWS::AuditManager::Assessment",
                    "Properties": {
                        "assessmentReportsDestination": {
                            "destination": {"Fn::ImportValue": "AuditManagerReportBucket"},
                            "destinationType": "S3"
                        },
                        "frameworkId": "arn:aws:auditmanager:us-east-1:068280491993:assessmentFramework/f5c5a0db-8a3e-4b1c-b1b0-a9a504a1ab8c",
                        "name": "SOC2 Compliance Assessment",
                        "scope": {
                            "awsAccounts": [
                                {
                                    "id": {"Ref": "AWS::AccountId"}
                                }
                            ],
                            "awsServices": [
                                {
                                    "serviceName": "EC2"
                                },
                                {
                                    "serviceName": "S3"
                                },
                                {
                                    "serviceName": "IAM"
                                },
                                {
                                    "serviceName": "CloudTrail"
                                },
                                {
                                    "serviceName": "Config"
                                },
                                {
                                    "serviceName": "KMS"
                                }
                            ]
                        },
                        "roles": [
                            {
                                "roleArn": {"Fn::ImportValue": "AuditManagerAdminRoleArn"},
                                "roleType": "PROCESS_OWNER"
                            }
                        ],
                        "status": "ACTIVE"
                    }
                }
            }
        }
        
        return json.dumps(template)
    
    def deploy_stackset(self, stackset_name, template, parameters=None, capabilities=None):
        """Deploy a CloudFormation StackSet to target accounts"""
        try:
            # Create StackSet with SELF_MANAGED permission model instead of SERVICE_MANAGED
            self.cloudformation_client.create_stack_set(
                StackSetName=stackset_name,
                Description=f"Audit Manager deployment - {stackset_name}",
                TemplateBody=template,
                Parameters=parameters or [],
                Capabilities=capabilities or ['CAPABILITY_NAMED_IAM'],
                PermissionModel='SELF_MANAGED'  # Changed from SERVICE_MANAGED
                # Removed AutoDeployment parameter which is only for SERVICE_MANAGED
            )
            print(f"Created StackSet: {stackset_name}")
            
            # Deploy to target accounts
            target_accounts = self.target_accounts
            if target_accounts == ['all']:
                target_accounts = self.get_all_accounts()
            
            # For SELF_MANAGED, we need to specify the admin role and execution role
            # Using default CloudFormation service roles
            admin_role_arn = "arn:aws:iam::aws:policy/service-role/AWSCloudFormationStackSetAdministrationRole"
            execution_role_name = "AWSCloudFormationStackSetExecutionRole"
            
            self.cloudformation_client.create_stack_instances(
                StackSetName=stackset_name,
                Accounts=target_accounts,
                Regions=[self.region],
                OperationPreferences={
                    'FailureTolerancePercentage': 10,
                    'MaxConcurrentPercentage': 25
                }
                # For SELF_MANAGED, the execution role is assumed by default
            )
            print(f"Deploying {stackset_name} to {len(target_accounts)} accounts")
            
            return True
        except ClientError as e:
            if 'AlreadyExistsException' in str(e):
                print(f"StackSet {stackset_name} already exists. Updating...")
                try:
                    # Update existing StackSet
                    self.cloudformation_client.update_stack_set(
                        StackSetName=stackset_name,
                        Description=f"Audit Manager deployment - {stackset_name}",
                        TemplateBody=template,
                        Parameters=parameters or [],
                        Capabilities=capabilities or ['CAPABILITY_NAMED_IAM'],
                        OperationPreferences={
                            'FailureTolerancePercentage': 10,
                            'MaxConcurrentPercentage': 25
                        }
                    )
                    print(f"Updated StackSet: {stackset_name}")
                    
                    # Create instances in accounts that don't have them
                    self.cloudformation_client.create_stack_instances(
                        StackSetName=stackset_name,
                        Accounts=target_accounts,
                        Regions=[self.region],
                        OperationPreferences={
                            'FailureTolerancePercentage': 10,
                            'MaxConcurrentPercentage': 25
                        }
                    )
                    print(f"Deploying {stackset_name} to {len(target_accounts)} accounts")
                    
                    return True
                except Exception as update_error:
                    print(f"Error updating StackSet: {update_error}")
                    return False
            else:
                print(f"Error creating StackSet: {e}")
                return False
    
    def enable_audit_manager_delegated_admin(self, delegated_admin_account_id):
        """Enable Audit Manager delegated administrator for centralized management"""
        try:
            # Register delegated administrator for Audit Manager
            self.organizations_client.register_delegated_administrator(
                AccountId=delegated_admin_account_id,
                ServicePrincipal='auditmanager.amazonaws.com'
            )
            print(f"Registered account {delegated_admin_account_id} as Audit Manager delegated administrator")
            return True
        except ClientError as e:
            if 'already a delegated administrator' in str(e):
                print(f"Account {delegated_admin_account_id} is already a delegated administrator for Audit Manager")
                return True
            else:
                print(f"Error registering delegated administrator: {e}")
                return False
    
    def deploy_audit_manager(self, delegated_admin_account_id=None):
        """Deploy Audit Manager across multiple accounts"""
        print("Starting AWS Audit Manager multi-account deployment")
        
        # Step 1: Deploy IAM roles for Audit Manager
        role_template = self.create_audit_manager_role()
        role_deployment = self.deploy_stackset(
            'AuditManagerServiceRole',
            role_template,
            capabilities=['CAPABILITY_NAMED_IAM']
        )
        
        if not role_deployment:
            print("Failed to deploy Audit Manager service roles")
            return False
        
        # Step 2: Deploy Audit Manager configuration
        config_template = self.create_audit_manager_config()
        config_deployment = self.deploy_stackset(
            'AuditManagerConfiguration',
            config_template,
            capabilities=['CAPABILITY_NAMED_IAM']
        )
        
        if not config_deployment:
            print("Failed to deploy Audit Manager configuration")
            return False
        
        # Step 3: Set up delegated administrator if specified
        if delegated_admin_account_id:
            delegated_admin_setup = self.enable_audit_manager_delegated_admin(delegated_admin_account_id)
            if not delegated_admin_setup:
                print("Failed to set up delegated administrator")
                return False
        
        print("AWS Audit Manager deployment completed successfully")
        return True

def main():
    parser = argparse.ArgumentParser(description='Deploy AWS Audit Manager across multiple accounts')
    parser.add_argument('--management-role', help='ARN of the management account role to assume')
    parser.add_argument('--target-accounts', help='Comma-separated list of target account IDs or "all" for all accounts')
    parser.add_argument('--region', default='us-east-1', help='AWS region for deployment')
    parser.add_argument('--delegated-admin', help='Account ID to set as Audit Manager delegated administrator')
    parser.add_argument('--profile', help='AWS CLI profile to use instead of assuming a role')
    
    args = parser.parse_args()
    
    if not args.target_accounts:
        print("Error: --target-accounts is required")
        parser.print_help()
        sys.exit(1)
    
    target_accounts = args.target_accounts.split(',') if args.target_accounts != 'all' else ['all']
    
    deployer = AuditManagerDeployer(
        management_role_arn=args.management_role,
        target_accounts=target_accounts,
        region=args.region,
        profile=args.profile
    )
    
    success = deployer.deploy_audit_manager(args.delegated_admin)
    
    if success:
        print("\nAudit Manager deployment completed successfully!")
        print("\nNext steps:")
        print("1. Log in to the AWS Management Console for each account")
        print("2. Navigate to AWS Audit Manager")
        print("3. Verify the service is enabled and configured correctly")
        print("4. Create assessments for your compliance frameworks")
    else:
        print("\nAudit Manager deployment encountered issues. Please check the logs.")
        sys.exit(1)

if __name__ == "__main__":
    main()
