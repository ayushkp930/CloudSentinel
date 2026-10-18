from cloudsentinel.rules.s3_rules import S3EffectivePublicAccessRule


def test_s3001_detects_effective_public_bucket() -> None:
    resource = {
        "resource_id": "arn:aws:s3:::public-bucket",
        "resource_type": "aws.s3.bucket",
        "configuration": {
            "public_access_block": {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            },
            "acl": "public-read",
            "policy_allows_public": False,
        },
    }
    outcome = S3EffectivePublicAccessRule().evaluate(resource)
    assert len(outcome.matches) == 1
    assert outcome.matches[0].evidence["acl_effectively_public"] is True


def test_s3001_public_acl_blocked_by_pab_is_safe() -> None:
    resource = {
        "resource_id": "arn:aws:s3:::blocked-bucket",
        "resource_type": "aws.s3.bucket",
        "configuration": {
            "public_access_block": {
                "block_public_acls": True,
                "ignore_public_acls": True,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            },
            "acl": "public-read",
            "policy_allows_public": True,
        },
    }
    outcome = S3EffectivePublicAccessRule().evaluate(resource)
    assert len(outcome.matches) == 0
    assert outcome.diagnostics == []


def test_s3001_missing_pab_emits_diagnostic() -> None:
    resource = {
        "resource_id": "arn:aws:s3:::incomplete-bucket",
        "resource_type": "aws.s3.bucket",
        "configuration": {"acl": "private"},
    }
    outcome = S3EffectivePublicAccessRule().evaluate(resource)
    assert len(outcome.matches) == 0
    assert len(outcome.diagnostics) == 1
