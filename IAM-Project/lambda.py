import boto3
import json
import os

iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

def lambda_handler(event, context):

    user = event['detail']['userIdentity'].get('userName', 'UNKNOWN')
    actions = []

    keys = iam.list_access_keys(UserName=user)['AccessKeyMetadata']
    for key in keys:
        iam.update_access_key(
            UserName=user,
            AccessKeyId=key['AccessKeyId'],
            Status='Inactive'
        )
        actions.append(f"Disabled key: {key['AccessKeyId']}")

    try:
        iam.update_login_profile(
            UserName=user,
            PasswordResetRequired=True
        )
        actions.append("Password reset forced")
    except:
        actions.append("No console password")

    mfa = iam.list_mfa_devices(UserName=user)['MFADevices']
    actions.append("MFA Enabled" if mfa else "MFA NOT enabled")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="IAM Auto Remediation Triggered",
        Message="\n".join(actions)
    )

    return {"status": "done"}
