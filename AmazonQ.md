# AWS Audit Manager Configuration Guide

This document provides a step-by-step guide on how to configure AWS Audit Manager using the scripts in this repository.

## Overview

AWS Audit Manager helps you continuously audit your AWS usage to simplify how you assess risk and compliance with regulations and industry standards. The scripts in this repository automate the deployment and configuration of AWS Audit Manager across single or multiple AWS accounts.

## Configuration Steps

### 1. Initial Setup

Before configuring AWS Audit Manager, ensure you have:

- AWS CLI installed and configured with appropriate permissions
- Python 3.6+ and Boto3 installed
- For multi-account setup: AWS Organizations configured

### 2. Deployment Options

You have two main options for deploying AWS Audit Manager:

#### Option A: Single Account Deployment

Use the `deploy_single_account.py` script to deploy AWS Audit Manager in a single AWS account:

```bash
python deploy_single_account.py --profile your-aws-profile
```

#### Option B: Multi-Account Deployment

Use the `deploy_audit_manager.py` script to deploy AWS Audit Manager across multiple accounts:

```bash
python deploy_audit_manager.py --management-role YourManagementRoleARN --target-accounts all
```

Or specify specific accounts:

```bash
python deploy_audit_manager.py --management-role YourManagementRoleARN --target-accounts 123456789012,234567890123
```

### 3. Designate a Delegated Administrator (Optional)

For multi-account setups, designate a security or compliance account as the delegated administrator:

```bash
python deploy_audit_manager.py --profile your-profile --target-accounts your-account-id --delegated-admin delegated-admin-account-id
```

### 4. Create Assessments

After deploying AWS Audit Manager, create assessments based on your compliance requirements:

#### SOC2 Assessment

Create a SOC2 assessment in a single account:

```bash
python create_soc2_single_account.py --profile your-profile
```

Or across multiple accounts:

```bash
python create_soc2_assessment.py --accounts all --role-name CrossAccountRole
```

### 5. Set Up Evidence Collection

Configure automated evidence collection to gather compliance data:

```bash
python audit_manager_evidence_collector.py --accounts your-account-id --profile your-profile
```

For specific assessments:

```bash
python audit_manager_evidence_collector.py --accounts your-account-id --profile your-profile --assessment-id your-assessment-id
```

### 6. Schedule Regular Evidence Collection

Set up a scheduled task or AWS EventBridge rule to run the evidence collector script regularly:

Example EventBridge rule (AWS CLI):

```bash
aws events put-rule --name "DailyAuditManagerEvidenceCollection" --schedule-expression "rate(1 day)"
```

## Best Practices

1. **IAM Permissions**: Use the principle of least privilege when creating IAM roles for Audit Manager
2. **Evidence Storage**: Configure secure S3 buckets with appropriate encryption for assessment reports
3. **Regular Reviews**: Schedule regular reviews of collected evidence and assessment status
4. **Notifications**: Set up SNS notifications for important assessment events
5. **Documentation**: Maintain documentation of your compliance framework and control mappings

## Troubleshooting

Common issues and solutions:

1. **Access Denied Errors**
   - Verify IAM permissions for the executing role
   - Check cross-account trust relationships

2. **Service Not Enabled**
   - Ensure AWS Audit Manager is enabled in each account
   - Verify service quotas and limits

3. **Missing Evidence**
   - Check that evidence sources are properly configured
   - Verify control mappings in your assessment

4. **Deployment Failures**
   - Review CloudFormation stack events for detailed error messages
   - Check AWS Organizations permissions for multi-account deployments

## Additional Configuration

For advanced configurations, you can modify the scripts to:

- Customize assessment frameworks
- Add custom controls
- Configure additional evidence sources
- Integrate with other AWS services like Security Hub or Config
