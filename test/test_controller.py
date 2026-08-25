import unittest
import os
import json
import shutil
from src.guardrails.action_schema import (
    GuardrailDecision,
    STATE_GUARDRAIL_APPROVED,
    STATE_ACTION_REJECTED,
    STATE_ESCALATE_HUMAN
)
from src.controller.cilium_policy import CiliumPolicyGenerator
from src.controller.executor import ActionExecutor, ActionExecutionResult

TEST_AUDIT_LOG = "logs/test_controller_audit.jsonl"
TEST_FORENSICS_FILE = "logs/forensics_compromised-pod-xyz.json"

class TestActionController(unittest.TestCase):

    def setUp(self):
        self.executor = ActionExecutor(
            namespace="test-namespace",
            audit_log_path=TEST_AUDIT_LOG,
            dry_run_mode=True
        )
        if os.path.exists(TEST_AUDIT_LOG):
            os.remove(TEST_AUDIT_LOG)
        if os.path.exists(TEST_FORENSICS_FILE):
            os.remove(TEST_FORENSICS_FILE)

    def tearDown(self):
        if os.path.exists(TEST_AUDIT_LOG):
            os.remove(TEST_AUDIT_LOG)
        if os.path.exists(TEST_FORENSICS_FILE):
            os.remove(TEST_FORENSICS_FILE)

    def test_cilium_policy_generator(self):
        """Test Cilium eBPF quarantine policy generation."""
        policy = CiliumPolicyGenerator.generate_cilium_quarantine_policy(
            pod_name="vulnerable-service-abc12",
            namespace="prod",
            app_label="vulnerable-service",
            mitre_technique="T1059",
            reason="Falco reverse shell alert"
        )
        
        self.assertEqual(policy["apiVersion"], "cilium.io/v2")
        self.assertEqual(policy["kind"], "CiliumNetworkPolicy")
        self.assertEqual(policy["metadata"]["name"], "aegis-quarantine-vulnerable-service-abc12")
        self.assertEqual(policy["metadata"]["annotations"]["aegis.io/mitre-ttp"], "T1059")
        self.assertEqual(policy["spec"]["ingress"], [])
        self.assertEqual(policy["spec"]["egress"], [])

        yaml_str = CiliumPolicyGenerator.to_yaml(policy)
        self.assertIn("kind: CiliumNetworkPolicy", yaml_str)
        self.assertIn("ingress: []", yaml_str)

    def test_execute_restart_pod(self):
        """Test RESTART_POD execution under dry-run mode."""
        decision = GuardrailDecision(
            approved=True,
            final_action="RESTART_POD",
            state=STATE_GUARDRAIL_APPROVED,
            reason="Pod experiencing high 500 error spike",
            confidence=0.92,
            original_action="RESTART_POD",
            target_pod="checkout-service-123",
            problem_type="SRE_BUG"
        )

        result = self.executor.execute_decision(decision)
        self.assertTrue(result.success)
        self.assertEqual(result.action, "RESTART_POD")
        self.assertEqual(result.status_code, "COMPLETED_DRY_RUN")
        self.assertTrue(result.health_verified)
        self.assertIn("Issued rollout restart command", result.details)

        # Check audit log
        self.assertTrue(os.path.exists(TEST_AUDIT_LOG))
        with open(TEST_AUDIT_LOG, "r") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["executed_action"], "RESTART_POD")
            self.assertTrue(entry["execution_success"])

    def test_execute_cilium_quarantine_ebpf_and_dfir_forensics(self):
        """Test CILIUM_QUARANTINE_EBPF execution and automated DFIR forensics snapshot creation."""
        decision = GuardrailDecision(
            approved=True,
            final_action="CILIUM_QUARANTINE_EBPF",
            state=STATE_GUARDRAIL_APPROVED,
            reason="Active security attack detected via Falco eBPF",
            confidence=0.98,
            original_action="RESTART_POD",
            target_pod="compromised-pod-xyz",
            problem_type="SECURITY_ATTACK",
            mitre_technique="T1059"
        )

        result = self.executor.execute_decision(decision)
        self.assertTrue(result.success)
        self.assertEqual(result.action, "CILIUM_QUARANTINE_EBPF")
        self.assertIsNotNone(result.policy_applied)
        self.assertIsNotNone(result.forensics_file)
        self.assertTrue(os.path.exists(result.forensics_file))

        # Verify DFIR forensics artifact contents
        with open(result.forensics_file, "r") as f:
            forensics_json = json.load(f)
            self.assertEqual(forensics_json["target_pod"], "compromised-pod-xyz")
            self.assertEqual(forensics_json["mitre_technique"], "T1059")
            self.assertIn("simulated_process_tree", forensics_json)
            self.assertIn("active_sockets", forensics_json)

    def test_execute_unquarantine_pod(self):
        """Test UNQUARANTINE_POD action reversibility."""
        decision = GuardrailDecision(
            approved=True,
            final_action="UNQUARANTINE_POD",
            state=STATE_GUARDRAIL_APPROVED,
            reason="Security review completed; restoring normal pod traffic",
            confidence=0.95,
            original_action="UNQUARANTINE_POD",
            target_pod="compromised-pod-xyz",
            problem_type="SECURITY_ATTACK"
        )

        result = self.executor.execute_decision(decision)
        self.assertTrue(result.success)
        self.assertEqual(result.action, "UNQUARANTINE_POD")
        self.assertEqual(result.status_code, "COMPLETED_DRY_RUN")
        self.assertIn("Removed CiliumNetworkPolicy", result.details)

    def test_execute_unapproved_decision_skipped(self):
        """Test that unapproved guardrail decision is skipped."""
        decision = GuardrailDecision(
            approved=False,
            final_action="ESCALATE",
            state=STATE_ACTION_REJECTED,
            reason="Action 'DELETE_NAMESPACE' is on blocklist",
            confidence=0.99,
            original_action="DELETE_NAMESPACE",
            target_pod="critical-pod",
            problem_type="SECURITY_ATTACK"
        )

        result = self.executor.execute_decision(decision)
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, "SKIPPED_NOT_APPROVED")
        self.assertIn("Guardrail decision not approved", result.details)


if __name__ == "__main__":
    unittest.main()
