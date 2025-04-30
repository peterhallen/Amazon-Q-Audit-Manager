#!/usr/bin/env python3
"""
AWS Resource Inventory Script for SOC2 Compliance Auditing

This script inventories resources across multiple AWS services and exports
the results to an Excel spreadsheet for compliance review.

Requirements:
- boto3
- pandas
- openpyxl

Usage:
python aws_resource_inventory.py [--profile PROFILE_NAME] [--regions REGION1,REGION2]
"""

import argparse
import boto3
import pandas as pd
import datetime
import threading
import concurrent.futures
import os
from botocore.exceptions import ClientError

class AWSResourceInventory:
    def __init__(self, profile=None, regions=None):
        self.profile = profile
        self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        
        if regions:
            self.regions = regions
        else:
            # Get all available regions
            ec2_client = self.session.client('ec2', region_name='us-east-1')
            self.regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        self.inventory = {}
        self.lock = threading.Lock()
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
    def get_account_id(self):
        """Get the AWS Account ID"""
        sts_client = self.session.client('sts')
        return sts_client.get_caller_identity()['Account']
    
    def collect_ec2_instances(self, region):
        """Collect EC2 instances in the specified region"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            instances = []
            
            paginator = ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        name = 'Unnamed'
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                        
                        instances.append({
                            'Region': region,
                            'InstanceId': instance['InstanceId'],
                            'Name': name,
                            'InstanceType': instance['InstanceType'],
                            'State': instance['State']['Name'],
                            'LaunchTime': instance.get('LaunchTime', ''),
                            'PrivateIpAddress': instance.get('PrivateIpAddress', ''),
                            'PublicIpAddress': instance.get('PublicIpAddress', '')
                        })
            
            with self.lock:
                self.inventory['EC2 Instances'] = self.inventory.get('EC2 Instances', []) + instances
                
        except ClientError as e:
            print(f"Error collecting EC2 instances in {region}: {e}")
    
    def collect_s3_buckets(self):
        """Collect S3 buckets"""
        try:
            s3_client = self.session.client('s3')
            buckets = []
            
            response = s3_client.list_buckets()
            
            for bucket in response['Buckets']:
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                    region = location['LocationConstraint'] or 'us-east-1'
                    
                    # Get bucket policy status if available
                    try:
                        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket['Name'])
                        public = policy_status['PolicyStatus']['IsPublic']
                    except ClientError:
                        public = 'Unknown'
                    
                    # Get encryption settings
                    try:
                        encryption = s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                        encryption_enabled = 'Yes'
                    except ClientError:
                        encryption_enabled = 'No'
                    
                    buckets.append({
                        'BucketName': bucket['Name'],
                        'CreationDate': bucket['CreationDate'],
                        'Region': region,
                        'PublicAccess': public,
                        'EncryptionEnabled': encryption_enabled
                    })
                except ClientError as e:
                    print(f"Error getting details for bucket {bucket['Name']}: {e}")
                    buckets.append({
                        'BucketName': bucket['Name'],
                        'CreationDate': bucket['CreationDate'],
                        'Region': 'Error',
                        'PublicAccess': 'Error',
                        'EncryptionEnabled': 'Error'
                    })
            
            self.inventory['S3 Buckets'] = buckets
                
        except ClientError as e:
            print(f"Error collecting S3 buckets: {e}")
    
    def collect_rds_instances(self, region):
        """Collect RDS instances in the specified region"""
        try:
            rds_client = self.session.client('rds', region_name=region)
            instances = []
            
            paginator = rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    instances.append({
                        'Region': region,
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'Engine': instance['Engine'],
                        'EngineVersion': instance['EngineVersion'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'StorageEncrypted': instance['StorageEncrypted'],
                        'MultiAZ': instance['MultiAZ'],
                        'PubliclyAccessible': instance['PubliclyAccessible']
                    })
            
            with self.lock:
                self.inventory['RDS Instances'] = self.inventory.get('RDS Instances', []) + instances
                
        except ClientError as e:
            print(f"Error collecting RDS instances in {region}: {e}")
    
    def collect_iam_users(self):
        """Collect IAM users"""
        try:
            iam_client = self.session.client('iam')
            users = []
            
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    # Get access keys for each user
                    try:
                        access_keys = iam_client.list_access_keys(UserName=user['UserName'])
                        access_key_count = len(access_keys['AccessKeyMetadata'])
                        
                        # Check if any access keys are active
                        active_keys = sum(1 for key in access_keys['AccessKeyMetadata'] 
                                         if key['Status'] == 'Active')
                    except ClientError:
                        access_key_count = 'Error'
                        active_keys = 'Error'
                    
                    # Get MFA devices
                    try:
                        mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])
                        mfa_enabled = len(mfa_devices['MFADevices']) > 0
                    except ClientError:
                        mfa_enabled = 'Error'
                    
                    users.append({
                        'UserName': user['UserName'],
                        'UserId': user['UserId'],
                        'CreateDate': user['CreateDate'],
                        'PasswordLastUsed': user.get('PasswordLastUsed', 'Never'),
                        'AccessKeyCount': access_key_count,
                        'ActiveAccessKeys': active_keys,
                        'MFAEnabled': mfa_enabled
                    })
            
            self.inventory['IAM Users'] = users
                
        except ClientError as e:
            print(f"Error collecting IAM users: {e}")
    
    def collect_security_groups(self, region):
        """Collect security groups in the specified region"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            security_groups = []
            
            paginator = ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    # Check for potentially risky rules (0.0.0.0/0)
                    inbound_public_access = False
                    for permission in sg.get('IpPermissions', []):
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                inbound_public_access = True
                                break
                    
                    security_groups.append({
                        'Region': region,
                        'GroupId': sg['GroupId'],
                        'GroupName': sg['GroupName'],
                        'Description': sg['Description'],
                        'VpcId': sg.get('VpcId', 'Default'),
                        'PublicInboundAccess': inbound_public_access
                    })
            
            with self.lock:
                self.inventory['Security Groups'] = self.inventory.get('Security Groups', []) + security_groups
                
        except ClientError as e:
            print(f"Error collecting security groups in {region}: {e}")
    
    def collect_lambda_functions(self, region):
        """Collect Lambda functions in the specified region"""
        try:
            lambda_client = self.session.client('lambda', region_name=region)
            functions = []
            
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    functions.append({
                        'Region': region,
                        'FunctionName': function['FunctionName'],
                        'Runtime': function.get('Runtime', 'Unknown'),
                        'Role': function['Role'],
                        'Handler': function.get('Handler', 'Unknown'),
                        'CodeSize': function['CodeSize'],
                        'LastModified': function['LastModified'],
                        'Timeout': function['Timeout'],
                        'MemorySize': function['MemorySize']
                    })
            
            with self.lock:
                self.inventory['Lambda Functions'] = self.inventory.get('Lambda Functions', []) + functions
                
        except ClientError as e:
            print(f"Error collecting Lambda functions in {region}: {e}")
    
    def collect_cloudtrail_trails(self):
        """Collect CloudTrail trails"""
        try:
            # CloudTrail is a global service but trails can be region-specific
            trails = []
            
            for region in self.regions:
                try:
                    cloudtrail_client = self.session.client('cloudtrail', region_name=region)
                    response = cloudtrail_client.describe_trails()
                    
                    for trail in response['trailList']:
                        # Get trail status
                        try:
                            status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                            is_logging = status['IsLogging']
                        except ClientError:
                            is_logging = 'Unknown'
                        
                        trails.append({
                            'Name': trail['Name'],
                            'HomeRegion': trail['HomeRegion'],
                            'S3BucketName': trail['S3BucketName'],
                            'IsMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                            'LogFileValidationEnabled': trail.get('LogFileValidationEnabled', False),
                            'IsLogging': is_logging
                        })
                except ClientError as e:
                    print(f"Error collecting CloudTrail trails in {region}: {e}")
            
            self.inventory['CloudTrail Trails'] = trails
                
        except Exception as e:
            print(f"Error collecting CloudTrail trails: {e}")
    
    def collect_kms_keys(self, region):
        """Collect KMS keys in the specified region"""
        try:
            kms_client = self.session.client('kms', region_name=region)
            keys = []
            
            paginator = kms_client.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    try:
                        key_info = kms_client.describe_key(KeyId=key['KeyId'])
                        key_metadata = key_info['KeyMetadata']
                        
                        keys.append({
                            'Region': region,
                            'KeyId': key_metadata['KeyId'],
                            'Description': key_metadata.get('Description', ''),
                            'Enabled': key_metadata['Enabled'],
                            'KeyState': key_metadata['KeyState'],
                            'KeyUsage': key_metadata['KeyUsage'],
                            'Origin': key_metadata['Origin'],
                            'CreationDate': key_metadata['CreationDate']
                        })
                    except ClientError as e:
                        print(f"Error describing KMS key {key['KeyId']}: {e}")
            
            with self.lock:
                self.inventory['KMS Keys'] = self.inventory.get('KMS Keys', []) + keys
                
        except ClientError as e:
            print(f"Error collecting KMS keys in {region}: {e}")
    
    def collect_dynamodb_tables(self, region):
        """Collect DynamoDB tables in the specified region"""
        try:
            dynamodb_client = self.session.client('dynamodb', region_name=region)
            tables = []
            
            paginator = dynamodb_client.get_paginator('list_tables')
            for page in paginator.paginate():
                for table_name in page['TableNames']:
                    try:
                        table_info = dynamodb_client.describe_table(TableName=table_name)
                        table = table_info['Table']
                        
                        tables.append({
                            'Region': region,
                            'TableName': table['TableName'],
                            'Status': table['TableStatus'],
                            'CreationDateTime': table['CreationDateTime'],
                            'ProvisionedThroughput': f"R: {table['ProvisionedThroughput'].get('ReadCapacityUnits', 'N/A')}, W: {table['ProvisionedThroughput'].get('WriteCapacityUnits', 'N/A')}",
                            'TableSizeBytes': table.get('TableSizeBytes', 'N/A'),
                            'ItemCount': table.get('ItemCount', 'N/A')
                        })
                    except ClientError as e:
                        print(f"Error describing DynamoDB table {table_name}: {e}")
            
            with self.lock:
                self.inventory['DynamoDB Tables'] = self.inventory.get('DynamoDB Tables', []) + tables
                
        except ClientError as e:
            print(f"Error collecting DynamoDB tables in {region}: {e}")
    
    def collect_all_resources(self):
        """Collect all AWS resources"""
        print("Starting AWS resource inventory collection...")
        account_id = self.get_account_id()
        print(f"Collecting resources for AWS Account: {account_id}")
        
        # Collect global resources
        print("Collecting global resources...")
        self.collect_s3_buckets()
        self.collect_iam_users()
        self.collect_cloudtrail_trails()
        
        # Collect regional resources using thread pool
        print(f"Collecting regional resources across {len(self.regions)} regions...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(self.regions))) as executor:
            # EC2 Instances
            print("Collecting EC2 instances...")
            futures = [executor.submit(self.collect_ec2_instances, region) for region in self.regions]
            concurrent.futures.wait(futures)
            
            # Security Groups
            print("Collecting security groups...")
            futures = [executor.submit(self.collect_security_groups, region) for region in self.regions]
            concurrent.futures.wait(futures)
            
            # RDS Instances
            print("Collecting RDS instances...")
            futures = [executor.submit(self.collect_rds_instances, region) for region in self.regions]
            concurrent.futures.wait(futures)
            
            # Lambda Functions
            print("Collecting Lambda functions...")
            futures = [executor.submit(self.collect_lambda_functions, region) for region in self.regions]
            concurrent.futures.wait(futures)
            
            # KMS Keys
            print("Collecting KMS keys...")
            futures = [executor.submit(self.collect_kms_keys, region) for region in self.regions]
            concurrent.futures.wait(futures)
            
            # DynamoDB Tables
            print("Collecting DynamoDB tables...")
            futures = [executor.submit(self.collect_dynamodb_tables, region) for region in self.regions]
            concurrent.futures.wait(futures)
        
        print("Resource collection complete!")
    
    def export_to_excel(self, output_path=None):
        """Export the inventory to an Excel file"""
        if not output_path:
            account_id = self.get_account_id()
            output_path = f"aws_inventory_{account_id}_{self.timestamp}.xlsx"
        
        print(f"Exporting inventory to {output_path}...")
        
        def convert_timezone_aware_datetimes(obj):
            """Convert timezone-aware datetime objects to timezone-naive"""
            if isinstance(obj, datetime.datetime) and obj.tzinfo is not None:
                return obj.replace(tzinfo=None)
            return obj
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Create a summary sheet
            summary_data = {
                'Resource Type': [],
                'Count': [],
                'Regions': []
            }
            
            for resource_type, resources in self.inventory.items():
                summary_data['Resource Type'].append(resource_type)
                summary_data['Count'].append(len(resources))
                
                if resource_type in ['S3 Buckets', 'IAM Users', 'CloudTrail Trails']:
                    summary_data['Regions'].append('Global')
                else:
                    regions = set(item['Region'] for item in resources if 'Region' in item)
                    summary_data['Regions'].append(', '.join(regions))
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Create a sheet for each resource type
            for resource_type, resources in self.inventory.items():
                if resources:
                    # Convert timezone-aware datetimes to timezone-naive
                    processed_resources = []
                    for resource in resources:
                        processed_resource = {}
                        for key, value in resource.items():
                            processed_resource[key] = convert_timezone_aware_datetimes(value)
                        processed_resources.append(processed_resource)
                    
                    df = pd.DataFrame(processed_resources)
                    df.to_excel(writer, sheet_name=resource_type[:31], index=False)  # Excel sheet names limited to 31 chars
        
        print(f"Inventory exported to {output_path}")
        return output_path

def main():
    parser = argparse.ArgumentParser(description='AWS Resource Inventory for SOC2 Compliance')
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--regions', help='Comma-separated list of AWS regions to inventory')
    parser.add_argument('--output', help='Output file path for the Excel inventory')
    args = parser.parse_args()
    
    regions = args.regions.split(',') if args.regions else None
    
    inventory = AWSResourceInventory(profile=args.profile, regions=regions)
    inventory.collect_all_resources()
    output_file = inventory.export_to_excel(args.output)
    
    print(f"\nAWS Resource Inventory Complete!")
    print(f"Inventory saved to: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    main()
