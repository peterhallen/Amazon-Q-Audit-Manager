# AWS Audit Manager Configuration Guide

This repository contains scripts and tools to help you configure and manage AWS Audit Manager across your AWS accounts. AWS Audit Manager helps you continuously audit your AWS usage to simplify how you assess risk and compliance with regulations and industry standards.

## Prerequisites

Before using these scripts, ensure you have:

1. AWS CLI installed and configured
2. Python 3.6+ installed
3. Boto3 library installed (`pip install boto3`)
4. Appropriate IAM permissions to manage AWS Audit Manager
5. For multi-account setup: AWS Organizations configured

## Available Scripts

### 1. Deploy Audit Manager (`deploy_audit_manager.py`)

This script helps deploy and configure AWS Audit Manager across multiple AWS accounts using AWS Organizations and CloudFormation StackSets.

**Usage:**
```bash
python deploy_audit_manager.py --management-role YourManagementRoleARN --target-accounts all|comma,separated,account,ids
```

**Options:**
- `--management-role`: ARN of the management account role to assume
- `--target-accounts`: Comma-separated list of target account IDs or "all" for all accounts
- `--region`: AWS region for deployment (default: us-east-1)
- `--delegated-admin`: Account ID to set as Audit Manager delegated administrator
- `--profile`: AWS CLI profile to use instead of assuming a role

### 2. Create SOC2 Assessment (`create_soc2_assessment.py`)

This script creates SOC2 assessments across multiple AWS accounts using AWS Audit Manager.

**Usage:**
```bash
python create_soc2_assessment.py --accounts all|comma,separated,account,ids --role-name CrossAccountRole
```

**Options:**
- `--accounts`: Comma-separated list of account IDs or "all" for all accounts
- `--role-name`: Name of the IAM role to assume in target accounts
- `--region`: AWS region for Audit Manager (default: us-east-1)
- `--profile`: AWS CLI profile to use instead of assuming a role

### 3. Evidence Collector (`audit_manager_evidence_collector.py`)

This script automates the collection of evidence for AWS Audit Manager assessments across multiple AWS accounts.

**Usage:**
```bash
python audit_manager_evidence_collector.py --accounts all|comma,separated,account,ids --role-name CrossAccountRole
```

**Options:**
- `--accounts`: Comma-separated list of account IDs or "all" for all accounts
- `--role-name`: Name of the IAM role to assume in target accounts
- `--region`: AWS region for Audit Manager (default: us-east-1)
- `--assessment-id`: Specific assessment ID to collect evidence for (optional)
- `--profile`: AWS CLI profile to use instead of assuming a role

### 4. Single Account Scripts

- `create_soc2_single_account.py`: Creates SOC2 assessment in a single account
- `deploy_single_account.py`: Deploys Audit Manager in a single account

## Setup Instructions

### Step 1: Configure AWS Audit Manager in Management Account

1. Deploy Audit Manager in your management account:
```bash
python deploy_audit_manager.py --profile your-profile --target-accounts your-account-id
```

2. Designate a delegated administrator (optional):
```bash
python deploy_audit_manager.py --profile your-profile --target-accounts your-account-id --delegated-admin delegated-admin-account-id
```

### Step 2: Create SOC2 Assessment

Create a SOC2 assessment in your account(s):
```bash
python create_soc2_assessment.py --accounts your-account-id --profile your-profile
```

### Step 3: Collect Evidence

Set up regular evidence collection:
```bash
python audit_manager_evidence_collector.py --accounts your-account-id --profile your-profile
```

## Best Practices

1. **IAM Roles**: Create dedicated IAM roles with least privilege for Audit Manager operations
2. **Delegated Administrator**: For multi-account setups, designate a security/compliance account as delegated administrator
3. **Evidence Collection**: Schedule regular evidence collection using AWS EventBridge
4. **Assessment Reports**: Generate and store assessment reports in a dedicated S3 bucket with appropriate encryption
5. **Notifications**: Configure SNS notifications for assessment status changes

## Troubleshooting

- **Access Denied Errors**: Verify IAM permissions and cross-account roles
- **Service Not Enabled**: Ensure Audit Manager is enabled in each account
- **Missing Evidence**: Check control mapping and evidence sources
- **StackSet Failures**: Review CloudFormation events for detailed error messages

## Additional Resources

- [AWS Audit Manager Documentation](https://docs.aws.amazon.com/audit-manager/latest/userguide/what-is.html)
- [AWS Audit Manager API Reference](https://docs.aws.amazon.com/audit-manager/latest/APIReference/Welcome.html)
- [AWS CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html)
