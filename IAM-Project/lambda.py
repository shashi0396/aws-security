import boto3
import os

iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
EXEMPT_USERS = os.environ.get('EXEMPT_IAM_USERS', '').split(',')

def lambda_handler(event, context):

    actions = []

    # Extract IAM username from CloudTrail (most reliable)
    user = event.get('detail', {}) \
                .get('requestParameters', {}) \
                .get('userName')

    if not user:
        return {
            "status": "skipped",
            "reason": "No IAM user found in event"
        }

    # Skip exempted service users
    if user in EXEMPT_USERS:
        return {
            "status": "skipped",
            "reason": f"{user} is an exempted service user"
        }

    # Disable all access keys for the user
    try:
        keys = iam.list_access_keys(UserName=user)['AccessKeyMetadata']
        for key in keys:
            iam.update_access_key(
                UserName=user,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
            actions.append(f"Disabled access key: {key['AccessKeyId']}")
    except iam.exceptions.NoSuchEntityException:
        return {
            "status": "error",
            "reason": f"IAM user {user} does not exist"
        }

    # Force console password reset (if console access exists)
    try:
        iam.update_login_profile(
            UserName=user,
            PasswordResetRequired=True
        )
        actions.append("Console password reset forced")
    except iam.exceptions.NoSuchEntityException:
        actions.append("No console access")

    # Check MFA status
    mfa_devices = iam.list_mfa_devices(UserName=user)['MFADevices']
    if mfa_devices:
        actions.append("MFA already enabled")
    else:
        actions.append("MFA NOT enabled - access restricted until enabled")

    # Send SNS alert
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="IAM Unauthorized Access Key Remediation",
        Message="\n".join(actions)
    )

    return {
        "status": "remediated",
        "user": user,
        "actions": actions
    }
