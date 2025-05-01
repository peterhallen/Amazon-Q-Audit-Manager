#!/bin/bash
# AWS Audit Manager Evidence Collection Scheduler
# This script runs the evidence collector for the SOC2 assessment

# Set variables
PROFILE="YOUR_AWS_PROFILE"
ACCOUNT_ID="YOUR_AWS_ACCOUNT_ID"
ASSESSMENT_ID="YOUR_ASSESSMENT_ID"
LOG_DIR="./logs"
DATE=$(date +"%Y-%m-%d")
LOG_FILE="${LOG_DIR}/evidence_collection_${DATE}.log"

# Create log directory if it doesn't exist
mkdir -p $LOG_DIR

# Run the evidence collector
echo "Starting evidence collection at $(date)" > $LOG_FILE
python ./audit_manager_evidence_collector.py --profile $PROFILE --accounts $ACCOUNT_ID --assessment-id $ASSESSMENT_ID >> $LOG_FILE 2>&1
echo "Evidence collection completed at $(date)" >> $LOG_FILE

# Exit with the status of the evidence collector
exit $?
