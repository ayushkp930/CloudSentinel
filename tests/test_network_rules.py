from cloudsentinel.rules.network_rules import (
    PublicIPv6AdminPortRule,
    PublicRDPRule,
    PublicSSHRule,
)


def test_net001_detects_public_ssh_ipv4() -> None:
    resource = {
        "resource_id": "sg-001",
        "resource_type": "aws.ec2.security_group",
        "configuration": {
            "inbound_permissions": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv4_ranges": ["0.0.0.0/0"]}
            ]
        },
    }
    outcome = PublicSSHRule().evaluate(resource)
    assert len(outcome.matches) == 1
    assert outcome.matches[0].evidence["cidr"] == "0.0.0.0/0"
    assert outcome.diagnostics == []


def test_net001_ignores_restricted_cidr() -> None:
    resource = {
        "resource_id": "sg-safe",
        "resource_type": "aws.ec2.security_group",
        "configuration": {
            "inbound_permissions": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv4_ranges": ["10.0.0.0/8"]}
            ]
        },
    }
    outcome = PublicSSHRule().evaluate(resource)
    assert len(outcome.matches) == 0
    assert outcome.diagnostics == []


def test_net001_missing_permissions_emits_diagnostic_not_safe() -> None:
    resource = {
        "resource_id": "sg-missing",
        "resource_type": "aws.ec2.security_group",
        "configuration": {},
    }
    outcome = PublicSSHRule().evaluate(resource)
    assert len(outcome.matches) == 0
    assert len(outcome.diagnostics) == 1


def test_net002_detects_public_rdp_ipv4() -> None:
    resource = {
        "resource_id": "sg-rdp",
        "resource_type": "aws.ec2.security_group",
        "configuration": {
            "inbound_permissions": [
                {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "ipv4_ranges": ["0.0.0.0/0"]}
            ]
        },
    }
    outcome = PublicRDPRule().evaluate(resource)
    assert len(outcome.matches) == 1
    assert outcome.matches[0].evidence["exposed_port"] == 3389


def test_net003_detects_ipv6_admin_exposure() -> None:
    resource = {
        "resource_id": "sg-ipv6",
        "resource_type": "aws.ec2.security_group",
        "configuration": {
            "inbound_permissions": [
                {"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv6_ranges": ["::/0"]}
            ]
        },
    }
    outcome = PublicIPv6AdminPortRule().evaluate(resource)
    assert len(outcome.matches) == 1
    assert outcome.matches[0].evidence["cidr_ipv6"] == "::/0"
