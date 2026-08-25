import unittest
import os
import json
from src.guardrails.validator import GuardrailEngine
from src.guardrails.action_schema import (
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN
)
from src.controller.executor import ActionExecutor
from src.brain.diagnostic_engine import DiagnosticEngine

TEST_EDGE_AUDIT = "logs/test_edge_audit.jsonl"

class TestEdgeCasesAndSystemBehavior(unittest.TestCase):

    def setUp(self):
        self.guardrail = GuardrailEngine(min_confidence_threshold=0.70, max_restarts_per_hour=3)
        self.executor = ActionExecutor(namespace="aegis-target", audit_log_path=TEST_EDGE_AUDIT, dry_run_mode=True)

    def tearDown(self):
        if os.path.exists(TEST_EDGE_AUDIT):
            os.remove(TEST_EDGE_AUDIT)

    def test_case_1_known_operational_bug(self):
        """Known problem behavior: High confidence operational bug -> Auto RESTART_POD."""
        verdict = {
            "target_pod": "aegis-storefront-prod-1",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "RESTART_POD",
            "confidence": 0.90,
            "mitre_technique": None
        }
        decision = self.guardrail.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        self.assertEqual(decision.state, STATE_GUARDRAIL_APPROVED)

        exec_res = self.executor.execute_decision(decision)
        self.assertTrue(exec_res.success)
        self.assertEqual(exec_res.action, "RESTART_POD")

    def test_case_2_novel_unseen_problem_low_confidence(self):
        """Novel/Unseen problem behavior: Low AI confidence -> Auto ESCALATE to human, NO action executed."""
        verdict = {
            "target_pod": "aegis-storefront-prod-2",
            "problem_type": "UNKNOWN_ANOMALY",
            "recommended_action": "RESTART_POD",
            "confidence": 0.45,  # Low confidence due to novel pattern
            "mitre_technique": None
        }
        decision = self.guardrail.validate_verdict(verdict)
        self.assertFalse(decision.approved)
        self.assertEqual(decision.state, STATE_ESCALATE_HUMAN)
        self.assertEqual(decision.final_action, "ESCALATE")

        exec_res = self.executor.execute_decision(decision)
        self.assertFalse(exec_res.success)
        self.assertEqual(exec_res.status_code, "SKIPPED_NOT_APPROVED")

    def test_case_3_catastrophic_hallucination_prevention(self):
        """Unique out-of-distribution problem behavior: Destructive recommendation -> HARD REJECTED."""
        verdict = {
            "target_pod": "aegis-storefront-prod-3",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "DELETE_NAMESPACE",
            "confidence": 0.95
        }
        decision = self.guardrail.validate_verdict(verdict)
        self.assertFalse(decision.approved)
        self.assertEqual(decision.state, STATE_ACTION_REJECTED)
        self.assertEqual(decision.final_action, "ESCALATE")
        self.assertIn("blocked by catastrophic safety filter", decision.reason)

    def test_case_4_quarantine_capacity_compensation(self):
        """Security quarantine + capacity compensation behavior: Quarantine pod & scale remaining deployment."""
        quarantine_verdict = {
            "target_pod": "aegis-storefront-prod-1",
            "problem_type": "SECURITY_ATTACK",
            "recommended_action": "CILIUM_QUARANTINE_EBPF",
            "confidence": 0.98,
            "mitre_technique": "T1059"
        }
        d1 = self.guardrail.validate_verdict(quarantine_verdict)
        r1 = self.executor.execute_decision(d1)
        self.assertTrue(r1.success)
        self.assertEqual(r1.action, "CILIUM_QUARANTINE_EBPF")

        # Capacity compensation: Scale remaining deployment replicas to prevent traffic bottleneck
        scale_verdict = {
            "target_pod": "aegis-storefront-prod-2",
            "problem_type": "RESOURCE_CAPACITY",
            "recommended_action": "SCALE_DEPLOYMENT",
            "confidence": 0.91
        }
        d2 = self.guardrail.validate_verdict(scale_verdict)
        r2 = self.executor.execute_decision(d2)
        self.assertTrue(r2.success)
        self.assertEqual(r2.action, "SCALE_DEPLOYMENT")


if __name__ == "__main__":
    unittest.main()
