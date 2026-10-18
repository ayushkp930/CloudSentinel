from typing import Any

from cloudsentinel.rules.base import DetectionRule, RuleEvaluationOutcome, RuleMatch


def _port_in_range(target_port: int, protocol: Any, from_port: Any, to_port: Any) -> bool:
    """Check if target TCP port falls within permission protocol and port range."""
    if str(protocol).lower() not in ("tcp", "-1", "all"):
        return False
    if str(protocol).lower() in ("-1", "all"):
        return True
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return False
    return from_port <= target_port <= to_port


class PublicSSHRule(DetectionRule):
    rule_id = "NET-001"
    title = "SSH (TCP/22) is reachable from any IPv4 address (0.0.0.0/0)"
    description = "Inbound security group rule allows unrestricted IPv4 SSH access."
    applicable_resource_type = "aws.ec2.security_group"
    default_severity = "High"
    recommendation = "Restrict inbound TCP port 22 to approved bastion/VPN CIDR ranges and re-scan."

    def evaluate(self, resource: dict[str, Any]) -> RuleEvaluationOutcome:
        res_id = str(resource.get("resource_id", "unknown"))
        outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=res_id)
        config = resource.get("configuration", {})
        perms = config.get("inbound_permissions")

        if not isinstance(perms, list):
            outcome.diagnostics.append(
                f"{self.rule_id}: Missing or invalid 'inbound_permissions' list on {res_id}; cannot assume safe."
            )
            return outcome

        for perm in perms:
            if not isinstance(perm, dict):
                outcome.diagnostics.append(f"{self.rule_id}: Malformed permission entry in {res_id}.")
                continue
            protocol = perm.get("protocol")
            from_port = perm.get("from_port")
            to_port = perm.get("to_port")
            ipv4_ranges = perm.get("ipv4_ranges")

            if ipv4_ranges is None or not isinstance(ipv4_ranges, list):
                outcome.diagnostics.append(f"{self.rule_id}: Missing 'ipv4_ranges' in permission on {res_id}.")
                continue

            if _port_in_range(22, protocol, from_port, to_port) and "0.0.0.0/0" in ipv4_ranges:
                outcome.matches.append(
                    RuleMatch(
                        matched=True,
                        evidence={
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": "0.0.0.0/0",
                            "exposed_port": 22,
                        },
                        reason="Inbound rule permits TCP port 22 from 0.0.0.0/0.",
                        impact_score=30,
                        exposure_score=30,
                        privilege_score=14,
                    )
                )
        return outcome


class PublicRDPRule(DetectionRule):
    rule_id = "NET-002"
    title = "RDP (TCP/3389) is reachable from any IPv4 address (0.0.0.0/0)"
    description = "Inbound security group rule allows unrestricted IPv4 Remote Desktop access."
    applicable_resource_type = "aws.ec2.security_group"
    default_severity = "High"
    recommendation = "Restrict inbound TCP port 3389 to internal management subnets or VPN gateways."

    def evaluate(self, resource: dict[str, Any]) -> RuleEvaluationOutcome:
        res_id = str(resource.get("resource_id", "unknown"))
        outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=res_id)
        config = resource.get("configuration", {})
        perms = config.get("inbound_permissions")

        if not isinstance(perms, list):
            outcome.diagnostics.append(
                f"{self.rule_id}: Missing or invalid 'inbound_permissions' list on {res_id}; cannot assume safe."
            )
            return outcome

        for perm in perms:
            if not isinstance(perm, dict):
                outcome.diagnostics.append(f"{self.rule_id}: Malformed permission entry in {res_id}.")
                continue
            protocol = perm.get("protocol")
            from_port = perm.get("from_port")
            to_port = perm.get("to_port")
            ipv4_ranges = perm.get("ipv4_ranges")

            if ipv4_ranges is None or not isinstance(ipv4_ranges, list):
                outcome.diagnostics.append(f"{self.rule_id}: Missing 'ipv4_ranges' in permission on {res_id}.")
                continue

            if _port_in_range(3389, protocol, from_port, to_port) and "0.0.0.0/0" in ipv4_ranges:
                outcome.matches.append(
                    RuleMatch(
                        matched=True,
                        evidence={
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": "0.0.0.0/0",
                            "exposed_port": 3389,
                        },
                        reason="Inbound rule permits TCP port 3389 from 0.0.0.0/0.",
                        impact_score=32,
                        exposure_score=30,
                        privilege_score=14,
                    )
                )
        return outcome


class PublicIPv6AdminPortRule(DetectionRule):
    rule_id = "NET-003"
    title = "Administrative port (SSH/RDP) is exposed to IPv6 world (::/0)"
    description = "Inbound security group rule allows unrestricted IPv6 access to TCP/22 or TCP/3389."
    applicable_resource_type = "aws.ec2.security_group"
    default_severity = "High"
    recommendation = "Remove ::/0 from administrative ports and restrict IPv6 access to trusted prefixes."

    def evaluate(self, resource: dict[str, Any]) -> RuleEvaluationOutcome:
        res_id = str(resource.get("resource_id", "unknown"))
        outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=res_id)
        config = resource.get("configuration", {})
        perms = config.get("inbound_permissions")

        if not isinstance(perms, list):
            outcome.diagnostics.append(
                f"{self.rule_id}: Missing or invalid 'inbound_permissions' list on {res_id}; cannot assume safe."
            )
            return outcome

        for perm in perms:
            if not isinstance(perm, dict):
                outcome.diagnostics.append(f"{self.rule_id}: Malformed permission entry in {res_id}.")
                continue
            protocol = perm.get("protocol")
            from_port = perm.get("from_port")
            to_port = perm.get("to_port")
            ipv6_ranges = perm.get("ipv6_ranges")

            if ipv6_ranges is None or not isinstance(ipv6_ranges, list):
                outcome.diagnostics.append(f"{self.rule_id}: Missing 'ipv6_ranges' in permission on {res_id}.")
                continue

            if "::/0" in ipv6_ranges:
                for admin_port in (22, 3389):
                    if _port_in_range(admin_port, protocol, from_port, to_port):
                        outcome.matches.append(
                            RuleMatch(
                                matched=True,
                                evidence={
                                    "protocol": protocol,
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "cidr_ipv6": "::/0",
                                    "exposed_port": admin_port,
                                },
                                reason=f"Inbound rule permits TCP port {admin_port} from IPv6 ::/0.",
                                impact_score=30,
                                exposure_score=30,
                                privilege_score=14,
                            )
                        )
        return outcome
