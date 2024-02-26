from unittest.mock import patch

import pytest
from pydantic import ValidationError
from sessiongpt.main import (
    IAMPolicyStatement,
    IAMSessionPolicy,
    main,
)


def test_iam_policy_statement():
    statement = IAMPolicyStatement(
        Sid="TestStatement",
        Effect="Allow",
        Action=["s3:ListBucket"],
        Resource=["arn:aws:s3:::example_bucket"],
    )
    assert statement.Sid == "TestStatement"
    assert statement.Effect == "Allow"
    assert "s3:ListBucket" in statement.Action
    assert "arn:aws:s3:::example_bucket" in statement.Resource


def test_iam_policy_statement_effect_validator():
    with pytest.raises(ValidationError):
        IAMPolicyStatement(
            Sid="TestStatement",
            Effect="InvalidEffect",
            Action=["s3:ListBucket"],
            Resource=["arn:aws:s3:::example_bucket"],
        )


def test_iam_session_policy():
    statement = IAMPolicyStatement(
        Sid="TestStatement",
        Effect="Allow",
        Action=["s3:ListBucket"],
        Resource=["arn:aws:s3:::example_bucket"],
    )
    session_policy = IAMSessionPolicy(Version="2012-10-17", Statement=[statement])
    assert session_policy.Version == "2012-10-17"
    assert len(session_policy.Statement) == 1


@patch("sessiongpt.main.typer.echo")
@patch("sessiongpt.main.marvin.cast")
def test_main(mock_cast, mock_echo):
    policy = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3BucketManagement",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketCORS",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
        "s3:PutBucketCORS",
        "s3:PutBucketLogging",
        "s3:PutBucketVersioning"
      ],
      "Resource": [
        "arn:aws:s3:::*"
      ]
    },
    {
      "Sid": "LambdaMemoryConfiguration",
      "Effect": "Allow",
      "Action": [
        "lambda:UpdateFunctionConfiguration"
      ],
      "Resource": [
        "arn:aws:lambda:*:*:function:*"
      ]
    },
    {
      "Sid": "DatabaseActions",
      "Effect": "Allow",
      "Action": [
        "rds:*",
        "dynamodb:*",
        "neptune-db:*",
        "redshift:*",
        "timestream:*",
        "qldb:*",
        "memorydb:*"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Sid": "PreventDatabaseDeletion",
      "Effect": "Deny",
      "Action": [
        "rds:DeleteDB*",
        "dynamodb:DeleteTable",
        "neptune-db:Delete*",
        "redshift:Delete*",
        "timestream:Delete*",
        "qldb:Delete*",
        "memorydb:Delete*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
    """
    mock_cast.return_value.model_dump_json.return_value = policy
    main(
        description="I want to create and manage S3 buckets, update my Lambda memory configuration. I also need to perform all database actions, but I don't want to delete any by accident."
    )
    mock_echo.assert_called_with(policy)
