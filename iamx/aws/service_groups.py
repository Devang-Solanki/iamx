"""
Pre-defined AWS service groups for targeted enumeration.
"""

SERVICE_GROUPS: dict[str, list[str]] = {
    "serverless": [
        "lambda", "apigateway", "apigatewayv2", "s3", "sns", "sqs",
        "dynamodb", "eventbridge", "stepfunctions",
    ],
    "compute": [
        "ec2", "ecs", "eks", "autoscaling", "elasticloadbalancing",
        "elasticloadbalancingv2", "batch", "lightsail",
    ],
    "iam": [
        "iam", "sts", "identitystore", "accessanalyzer",
    ],
    "storage": [
        "s3", "s3control", "glacier", "backup", "efs", "fsx",
    ],
    "databases": [
        "rds", "dynamodb", "elasticache", "redshift", "docdb", "neptune", "keyspaces",
    ],
    "network": [
        "ec2", "route53", "route53domains", "cloudfront", "wafv2",
        "waf", "shield", "directconnect",
    ],
    "devops": [
        "codecommit", "codebuild", "codedeploy", "codepipeline",
        "codeartifact", "ecr", "cloudformation",
    ],
    "security": [
        "guardduty", "securityhub", "macie2", "inspector2", "detective",
        "kms", "secretsmanager", "ssm", "wafv2", "acm",
    ],
    "monitoring": [
        "cloudwatch", "cloudtrail", "xray",
    ],
    "ai": [
        "bedrock", "bedrockagent", "sagemaker", "rekognition",
        "comprehend", "textract", "translate",
    ],
}
