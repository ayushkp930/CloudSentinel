from cloudsentinel.rules.iam_rules import IAMBroadPermissionsRule


def test_iam001_detects_wildcard_admin_policy() -> None:
    resource = {
        "resource_id": "arn:aws:iam::000:policy/Admin",
        "resource_type": "aws.iam.policy",
        "configuration": {
            "statements": [
                {"sid": "FullAccess", "effect": "Allow", "actions": ["*"], "resources": ["*"]}
            ]
        },
    }
    outcome = IAMBroadPermissionsRule().evaluate(resource)
    assert len(outcome.matches) == 1
    assert outcome.matches[0].evidence["sid"] == "FullAccess"


def test_iam001_ignores_scoped_s3_read_policy() -> None:
    resource = {
        "resource_id": "arn:aws:iam::000:policy/S3Read",
        "resource_type": "aws.iam.policy",
        "configuration": {
            "statements": [
                {
                    "sid": "ReadBucket",
                    "effect": "Allow",
                    "actions": ["s3:GetObject"],
                    "resources": ["arn:aws:s3:::my-bucket/*"],
                }
            ]
        },
    }
    outcome = IAMBroadPermissionsRule().evaluate(resource)
    assert len(outcome.matches) == 0
    assert outcome.diagnostics == []
