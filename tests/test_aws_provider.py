from typing import Any

from botocore.exceptions import ClientError

from cloudsentinel.collectors.aws_provider import collect_aws_readonly_bundle
from cloudsentinel.engine.scanner import run_resource_scan


class _MockDeniedClient:
    """Simulates AWS IAM AccessDenied exceptions on all read calls (TC-10)."""

    def describe_security_groups(self, **kwargs: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Access Denied"}},
            "DescribeSecurityGroups",
        )

    def list_buckets(self) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListBuckets",
        )

    def list_policies(self, **kwargs: Any) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListPolicies",
        )


class _MockDeniedSession:
    def client(self, service_name: str, **kwargs: Any) -> _MockDeniedClient:
        return _MockDeniedClient()


class _MockPartialEC2SuccessSession:
    """Simulates EC2 returning an open SSH security group while S3/IAM are denied."""

    def client(self, service_name: str, **kwargs: Any) -> Any:
        if service_name == "ec2":
            return type(
                "MockEC2",
                (),
                {
                    "describe_security_groups": lambda self, **kw: {
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-mock-live-01",
                                "GroupName": "mock-ssh-open",
                                "IpPermissions": [
                                    {
                                        "IpProtocol": "tcp",
                                        "FromPort": 22,
                                        "ToPort": 22,
                                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                        "Ipv6Ranges": [],
                                    }
                                ],
                            }
                        ]
                    }
                },
            )()
        return _MockDeniedClient()


def test_tc10_aws_permission_denied_marks_scan_failed_not_clean() -> None:
    bundle = collect_aws_readonly_bundle(region="us-east-1", session=_MockDeniedSession())
    assert bundle.provenance_label == "AWS Read-only Scan"
    assert len(bundle.resources) == 0
    assert len(bundle.diagnostics) == 3

    scan_res = run_resource_scan(bundle)
    assert scan_res.status == "failed"
    assert len(scan_res.diagnostics) == 3


def test_tc10_partial_aws_collection_emits_findings_and_partial_status() -> None:
    bundle = collect_aws_readonly_bundle(
        region="us-east-1",
        session=_MockPartialEC2SuccessSession(),
    )
    assert len(bundle.resources) == 1
    assert len(bundle.diagnostics) == 2

    scan_res = run_resource_scan(bundle)
    assert scan_res.status == "partial"
    assert len(scan_res.findings) == 1
    assert scan_res.findings[0]["rule_id"] == "NET-001"
    assert scan_res.findings[0]["resource_id"] == "sg-mock-live-01"
