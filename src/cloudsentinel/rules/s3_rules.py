from typing import Any

from cloudsentinel.rules.base import DetectionRule, RuleEvaluationOutcome, RuleMatch

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


class S3EffectivePublicAccessRule(DetectionRule):
    rule_id = "S3-001"
    title = "S3 bucket effective configuration permits unintended public access"
    description = (
        "Evaluates S3 Public Access Block settings alongside bucket ACL and bucket policy "
        "indicators to determine effective public exposure."
    )
    applicable_resource_type = "aws.s3.bucket"
    default_severity = "Critical"
    recommendation = (
        "Enable all four S3 Public Access Block settings on the bucket/account and remove "
        "public ACLs or wildcard principal bucket policy statements."
    )

    def evaluate(self, resource: dict[str, Any]) -> RuleEvaluationOutcome:
        res_id = str(resource.get("resource_id", "unknown"))
        outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=res_id)
        config = resource.get("configuration", {})

        pab = config.get("public_access_block")
        acl = config.get("acl")
        policy_public = config.get("policy_allows_public")

        if not isinstance(pab, dict) or acl is None or not isinstance(policy_public, bool):
            outcome.diagnostics.append(
                f"{self.rule_id}: Missing required S3 public access evidence on {res_id}; cannot assume safe."
            )
            return outcome

        required_pab_keys = {
            "block_public_acls",
            "ignore_public_acls",
            "block_public_policy",
            "restrict_public_buckets",
        }
        if not required_pab_keys.issubset(set(pab.keys())):
            outcome.diagnostics.append(
                f"{self.rule_id}: Incomplete 'public_access_block' fields on {res_id}; cannot assume safe."
            )
            return outcome

        acl_effectively_public = (str(acl) in PUBLIC_ACLS) and (
            not bool(pab.get("ignore_public_acls")) or not bool(pab.get("block_public_acls"))
        )
        policy_effectively_public = bool(policy_public) and (
            not bool(pab.get("restrict_public_buckets")) or not bool(pab.get("block_public_policy"))
        )

        if acl_effectively_public or policy_effectively_public:
            outcome.matches.append(
                RuleMatch(
                    matched=True,
                    evidence={
                        "acl": acl,
                        "policy_allows_public": policy_public,
                        "public_access_block": pab,
                        "acl_effectively_public": acl_effectively_public,
                        "policy_effectively_public": policy_effectively_public,
                    },
                    reason="Effective S3 bucket posture allows public access via unblocked ACL or bucket policy.",
                    impact_score=38,
                    exposure_score=30,
                    privilege_score=18,
                )
            )

        return outcome
