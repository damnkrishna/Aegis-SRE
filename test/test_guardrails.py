import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.guardrails import (
    GuardrailEngine,
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN,
)


class TestGuardrailEngine(unittest.TestCase):
    def setUp(self):
        self.engine = GuardrailEngine(min_confidence_threshold=0.70, max_restarts_per_hour=3)

    def test_approve_valid_operational_bug(self):
        verdict = {
            "target_pod": "checkout-service-prod",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "RESTART_POD",
            "confidence": 0.85
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        self.assertEqual(decision.final_action, "RESTART_POD")
        self.assertEqual(decision.state, STATE_GUARDRAIL_APPROVED)

    def test_approve_valid_security_attack(self):
        verdict = {
            "target_pod": "payment-service-prod",
            "problem_type": "SECURITY_ATTACK",
            "recommended_action": "CILIUM_QUARANTINE_EBPF",
            "confidence": 0.92,
            "mitre_technique": "T1059"
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        self.assertEqual(decision.final_action, "CILIUM_QUARANTINE_EBPF")
        self.assertEqual(decision.state, STATE_GUARDRAIL_APPROVED)

    def test_reject_catastrophic_blocklist_action(self):
        verdict = {
            "target_pod": "database-pod",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "DELETE_NAMESPACE",
            "confidence": 0.99
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertFalse(decision.approved)
        self.assertEqual(decision.final_action, "ESCALATE")
        self.assertEqual(decision.state, STATE_ACTION_REJECTED)
        self.assertIn("blocked by catastrophic safety filter", decision.reason)

    def test_escalate_low_confidence(self):
        verdict = {
            "target_pod": "frontend-service",
            "problem_type": "UNKNOWN",
            "recommended_action": "RESTART_POD",
            "confidence": 0.45
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertFalse(decision.approved)
        self.assertEqual(decision.final_action, "ESCALATE")
        self.assertEqual(decision.state, STATE_ESCALATE_HUMAN)
        self.assertIn("below minimum threshold", decision.reason)

    def test_rate_limiter_loop_prevention(self):
        verdict = {
            "target_pod": "flaky-service",
            "problem_type": "OPERATIONAL_BUG",
            "recommended_action": "RESTART_POD",
            "confidence": 0.88
        }
        # First 3 restarts should be approved
        for i in range(3):
            d = self.engine.validate_verdict(verdict)
            self.assertTrue(d.approved, f"Restart #{i+1} should be approved")

        # 4th restart within 1 hour should be rejected by rate limiter
        d4 = self.engine.validate_verdict(verdict)
        self.assertFalse(d4.approved)
        self.assertEqual(d4.final_action, "ESCALATE")
        self.assertEqual(d4.state, STATE_ACTION_REJECTED)
        self.assertTrue(d4.rate_limit_exceeded)
        self.assertIn("exceeded restart frequency cap", d4.reason)

    def test_security_attack_restart_override(self):
        verdict = {
            "target_pod": "compromised-pod",
            "problem_type": "SECURITY_ATTACK",
            "recommended_action": "RESTART_POD",  # Bad recommendation under attack
            "confidence": 0.88
        }
        decision = self.engine.validate_verdict(verdict)
        self.assertTrue(decision.approved)
        # Should override RESTART_POD with CILIUM_QUARANTINE_EBPF
        self.assertEqual(decision.final_action, "CILIUM_QUARANTINE_EBPF")
        self.assertIn("Overrode RESTART_POD", decision.reason)

if __name__ == "__main__":
    unittest.main()
