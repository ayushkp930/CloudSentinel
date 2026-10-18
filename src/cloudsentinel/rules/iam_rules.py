from typing import Any

from cloudsentinel.rules.base import DetectionRule, RuleEvaluationOutcome, RuleMatch


class IAMBroadPermissionsRule(DetectionRule):
    rule_id = "IAM-001"
    title = "IAM policy grants broad wildcard permissions (Action:* on Resource:*)"
    description = (
        "Detects IAM policy statements with Effect=Allow, wildcard actions, and wildcard "
        "resources without narrowing conditions."
    )
    applicable_resource_type = "aws.iam.policy"
    default_severity = "High"
    recommendation = (
        "Replace wildcard Action:* and Resource:* statements with least-privilege actions, "
        "scoped resource ARNs, and explicit IAM conditions."
    )

    def evaluate(self, resource: dict[str, Any]) -> RuleEvaluationOutcome:
        res_id = str(resource.get("resource_id", "unknown"))
        outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=res_id)
        config = resource.get("configuration", {})
        statements = config.get("statements")

        if not isinstance(statements, list) or len(statements) == 0:
            outcome.diagnostics.append(
                f"{self.rule_id}: Missing or empty 'statements' list on IAM policy {res_id}; cannot assume safe."
            )
            return outcome

        for idx, stmt in enumerate(statements):
            if not isinstance(stmt, dict):
                outcome.diagnostics.append(f"{self.rule_id}: Statement[{idx}] in {res_id} is not a dict.")
                continue

            effect = stmt.get("effect")
            actions = stmt.get("actions")
            resources = stmt.get("resources")
            conditions = stmt.get("conditions", {})

            if effect is None or not isinstance(actions, list) or not isinstance(resources, list):
                outcome.diagnostics.append(
                    f"{self.rule_id}: Statement[{idx}] in {res_id} missing effect/actions/resources."
                )
                continue

            has_wildcard_action = "*" in actions or "iam:*" in actions
            has_wildcard_resource = "*" in resources
            is_unconstrained = not bool(conditions)

            if str(effect).lower() == "allow" and has_wildcard_action and has_wildcard_resource and is_unconstrained:
                outcome.matches.append(
                    RuleMatch(
                        matched=True,
                        evidence={
                            "sid": stmt.get("sid", f"Stmt-{idx}"),
                            "effect": effect,
                            "actions": actions,
                            "resources": resources,
                            "conditions": conditions,
                        },
                        reason="Policy statement grants unconstrained wildcard Allow permissions.",
                        impact_score=35,
                        exposure_score=15,
                        privilege_score=30,
                    )
                )

        return outcome
