import boto3
import datetime

def lambda_handler(event, context):
    print("Starting evidence collection for AWS Audit Manager")
    audit_manager = boto3.client('auditmanager')
    
    # Assessment ID from your SOC2 assessment
    assessment_id = "YOUR_ASSESSMENT_ID"
    
    try:
        # Get the assessment details
        assessment = audit_manager.get_assessment(assessmentId=assessment_id)
        
        evidence_count = 0
        # Process each control set and collect evidence
        for control_set in assessment['assessment']['framework']['controlSets']:
            control_set_id = control_set['id']
            control_set_name = control_set['description'] or control_set['id']
            print(f"Processing control set: {control_set_name}")
            
            for control in control_set['controls']:
                control_id = control['id']
                control_name = control['name']
                
                # Add manual evidence
                current_date = datetime.datetime.now().strftime('%Y-%m-%d')
                evidence_text = f"Automated evidence collection via AWS Lambda on {current_date}"
                
                audit_manager.batch_import_evidence_to_assessment_control(
                    assessmentId=assessment_id,
                    controlId=control_id,
                    controlSetId=control_set_id,
                    manualEvidence=[
                        {
                            "textResponse": evidence_text
                        }
                    ]
                )
                
                evidence_count += 1
                print(f"Added evidence for control: {control_name}")
        
        return {
            'statusCode': 200,
            'body': f'Evidence collection completed successfully. Added evidence for {evidence_count} controls.'
        }
    except Exception as e:
        print(f"Error collecting evidence: {str(e)}")
        raise e
