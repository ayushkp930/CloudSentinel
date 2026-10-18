from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)

from cloudsentinel.collectors.demo_provider import CollectionBundle
from cloudsentinel.utils.logging_config import get_logger

logger = get_logger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_security_group(sg: dict[str, Any], region: str) -> dict[str, Any]:
    """Convert Boto3 EC2 SecurityGroup dict into CloudSentinel normalized resource schema."""
    inbound_perms: list[dict[str, Any]] = []
    for perm in sg.get("IpPermissions", []):
        proto = str(perm.get("IpProtocol", "tcp"))
        from_port = perm.get("FromPort", 0 if proto in ("-1", "all") else -1)
        to_port = perm.get("ToPort", 65535 if proto in ("-1", "all") else -1)
        ipv4 = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
        ipv6 = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
        inbound_perms.append(
            {
                "protocol": proto,
                "from_port": from_port,
                "to_port": to_port,
                "ipv4_ranges": ipv4,
                "ipv6_ranges": ipv6,
            }
        )

    return {
        "resource_id": str(sg.get("GroupId", "unknown-sg")),
        "resource_type": "aws.ec2.security_group",
        "name": str(sg.get("GroupName", "unnamed-sg")),
        "region": region,
        "configuration": {"inbound_permissions": inbound_perms},
    }


def collect_aws_readonly_bundle(
    profile_name: str | None = None,
    region: str = "us-east-1",
    max_items_per_service: int = 25,
    session: Any | None = None,
) -> CollectionBundle:
    """
    Collect scoped, strictly READ-ONLY AWS resource configurations (EC2 SGs, S3 Buckets, IAM Policies).
    Captures permission errors (AccessDenied) and credential errors as diagnostics so the orchestrator
    marks the scan as 'partial' or 'failed' rather than falsely reporting a clean posture (TC-10).
    """
    collected_at = _utc_now_iso()
    resources: list[dict[str, Any]] = []
    diagnostics: list[str] = []

    try:
        aws_session = (
            session
            if session is not None
            else boto3.Session(profile_name=profile_name or None, region_name=region)
        )
    except (ProfileNotFound, BotoCoreError) as exc:
        return CollectionBundle(
            source="aws_readonly",
            provenance_label="AWS Read-only Scan",
            collected_at=collected_at,
            resources=[],
            events=[],
            diagnostics=[f"AWS Session initialization failed: {exc}"],
        )

    # 1. Read-Only EC2 Security Groups Collection
    try:
        ec2 = aws_session.client("ec2", region_name=region)
        resp = ec2.describe_security_groups(MaxResults=max(5, min(100, max_items_per_service)))
        for sg in resp.get("SecurityGroups", [])[:max_items_per_service]:
            resources.append(_normalize_security_group(sg, region=region))
    except (ClientError, NoCredentialsError, BotoCoreError) as exc:
        diagnostics.append(f"EC2 describe_security_groups failed ({region}): {exc}")

    # 2. Read-Only S3 Buckets Posture Collection
    try:
        s3 = aws_session.client("s3", region_name=region)
        buckets = s3.list_buckets().get("Buckets", [])[:max_items_per_service]
        for b in buckets:
            b_name = str(b.get("Name", ""))
            if not b_name:
                continue
            try:
                pab_resp = s3.get_public_access_block(Bucket=b_name)
                pab_cfg = pab_resp.get("PublicAccessBlockConfiguration", {})
                pab = {
                    "block_public_acls": bool(pab_cfg.get("BlockPublicAcls", False)),
                    "ignore_public_acls": bool(pab_cfg.get("IgnorePublicAcls", False)),
                    "block_public_policy": bool(pab_cfg.get("BlockPublicPolicy", False)),
                    "restrict_public_buckets": bool(pab_cfg.get("RestrictPublicBuckets", False)),
                }
            except ClientError as exc:
                err_code = exc.response.get("Error", {}).get("Code", "")
                if err_code == "NoSuchPublicAccessBlockConfiguration":
                    pab = {
                        "block_public_acls": False,
                        "ignore_public_acls": False,
                        "block_public_policy": False,
                        "restrict_public_buckets": False,
                    }
                else:
                    diagnostics.append(f"S3 get_public_access_block failed on '{b_name}': {exc}")
                    continue

            acl_label = "private"
            try:
                acl_resp = s3.get_bucket_acl(Bucket=b_name)
                for grant in acl_resp.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri:
                        acl_label = "public-read"
                        break
                    if "AuthenticatedUsers" in uri:
                        acl_label = "authenticated-read"
            except ClientError as exc:
                diagnostics.append(f"S3 get_bucket_acl failed on '{b_name}': {exc}")
                continue

            policy_public = False
            try:
                pol_status = s3.get_bucket_policy_status(Bucket=b_name)
                policy_public = bool(pol_status.get("PolicyStatus", {}).get("IsPublic", False))
            except ClientError as exc:
                err_code = exc.response.get("Error", {}).get("Code", "")
                if err_code != "NoSuchBucketPolicy":
                    diagnostics.append(f"S3 get_bucket_policy_status failed on '{b_name}': {exc}")
                    continue

            resources.append(
                {
                    "resource_id": f"arn:aws:s3:::{b_name}",
                    "resource_type": "aws.s3.bucket",
                    "name": b_name,
                    "region": region,
                    "configuration": {
                        "public_access_block": pab,
                        "acl": acl_label,
                        "policy_allows_public": policy_public,
                    },
                }
            )
    except (ClientError, NoCredentialsError, BotoCoreError) as exc:
        diagnostics.append(f"S3 list_buckets failed: {exc}")

    # 3. Read-Only IAM Customer-Managed Policies Collection
    try:
        iam = aws_session.client("iam")
        pol_list = iam.list_policies(Scope="Local", MaxItems=max_items_per_service).get("Policies", [])
        for pol in pol_list[:max_items_per_service]:
            arn = str(pol.get("Arn", ""))
            ver_id = str(pol.get("DefaultVersionId", "v1"))
            name = str(pol.get("PolicyName", "unnamed-policy"))
            try:
                ver_doc = (
                    iam.get_policy_version(PolicyArn=arn, VersionId=ver_id)
                    .get("PolicyVersion", {})
                    .get("Document", {})
                )
                raw_stmts = ver_doc.get("Statement", [])
                if isinstance(raw_stmts, dict):
                    raw_stmts = [raw_stmts]
                norm_stmts: list[dict[str, Any]] = []
                for idx, st in enumerate(raw_stmts):
                    actions = st.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    res_list = st.get("Resource", [])
                    if isinstance(res_list, str):
                        res_list = [res_list]
                    norm_stmts.append(
                        {
                            "sid": str(st.get("Sid", f"Stmt-{idx}")),
                            "effect": str(st.get("Effect", "Deny")),
                            "actions": list(actions),
                            "resources": list(res_list),
                            "conditions": st.get("Condition", {}) or {},
                        }
                    )
                resources.append(
                    {
                        "resource_id": arn,
                        "resource_type": "aws.iam.policy",
                        "name": name,
                        "region": "global",
                        "configuration": {"statements": norm_stmts},
                    }
                )
            except ClientError as exc:
                diagnostics.append(f"IAM get_policy_version failed on '{arn}': {exc}")
    except (ClientError, NoCredentialsError, BotoCoreError) as exc:
        diagnostics.append(f"IAM list_policies failed: {exc}")

    logger.info(
        "Completed AWS Read-only collection: %d resources, %d diagnostics",
        len(resources),
        len(diagnostics),
    )

    return CollectionBundle(
        source="aws_readonly",
        provenance_label="AWS Read-only Scan",
        collected_at=collected_at,
        resources=resources,
        events=[],
        diagnostics=diagnostics,
    )
