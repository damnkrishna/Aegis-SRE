import unittest
import os
import json
from src.brain.diagnostic_engine import DiagnosticEngine
from src.controller.executor import ActionExecutor
from src.guardrails.action_schema import STATE_GUARDRAIL_APPROVED

TEST_PIPELINE_AUDIT_LOG = "logs/test_pipeline_audit.jsonl"

class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        self.diagnostic_engine = DiagnosticEngine()
        self.executor = ActionExecutor(
            namespace="default",
            audit_log_path=TEST_PIPELINE_AUDIT_LOG,
            dry_run_mode=True
        )
        if os.path.exists(TEST_PIPELINE_AUDIT_LOG):
            os.remove(TEST_PIPELINE_AUDIT_LOG)

    def tearDown(self):
        if os.path.exists(TEST_PIPELINE_AUDIT_LOG):
            os.remove(TEST_PIPELINE_AUDIT_LOG)

    def test_e2e_operational_bug_remediation(self):
        """Tests end-to-end Bug Path: Alert -> Diagnosis -> Guardrail -> RESTART_POD Execution."""
        # 1. Run AI Diagnosis
        verdict = self.diagnostic_engine.diagnose_incident(
            pod_name="storefront-app-pod-123",
            alert_type="HTTP_500_SPIKE"
        )
        self.assertIn("guardrail_validation", verdict)
        self.assertTrue(verdict["guardrail_validation"]["approved"])
        self.assertEqual(verdict["guardrail_validation"]["final_action"], "RESTART_POD")

        # 2. Run Controller Execution
        decision = verdict["decision_object"]
        exec_result = self.executor.execute_decision(decision)
        self.assertTrue(exec_result.success)
        self.assertEqual(exec_result.action, "RESTART_POD")
        self.assertEqual(exec_result.status_code, "COMPLETED_DRY_RUN")

    def test_e2e_security_attack_remediation(self):
        """Tests end-to-end Attack Path: Falco Alert -> Diagnosis -> Guardrail Override -> CILIUM_QUARANTINE_EBPF Execution."""
        # 1. Run AI Diagnosis on Falco shell spawn alert
        verdict = self.diagnostic_engine.diagnose_incident(
            pod_name="compromised-cart-service",
            alert_type="falco_shell_spawn"
        )
        self.assertIn("guardrail_validation", verdict)
        self.assertTrue(verdict["guardrail_validation"]["approved"])
        self.assertEqual(verdict["guardrail_validation"]["final_action"], "CILIUM_QUARANTINE_EBPF")
        self.assertEqual(verdict["problem_type"], "SECURITY_ATTACK")

        # 2. Run Controller Execution
        decision = verdict["decision_object"]
        exec_result = self.executor.execute_decision(decision)
        self.assertTrue(exec_result.success)
        self.assertEqual(exec_result.action, "CILIUM_QUARANTINE_EBPF")
        self.assertIsNotNone(exec_result.policy_applied)
        self.assertEqual(exec_result.policy_applied["kind"], "CiliumNetworkPolicy")
        self.assertEqual(exec_result.policy_applied["spec"]["ingress"], [])
        self.assertEqual(exec_result.policy_applied["spec"]["egress"], [])


if __name__ == "__main__":
    unittest.main()
