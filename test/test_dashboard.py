import unittest
import os
from fastapi.testclient import TestClient
from src.dashboard.server import app

class TestDashboardServer(unittest.TestCase):
    """
    Test suite for Phase 7 Command Center Dashboard API, Chaos Simulation Triggers,
    and Human-in-the-Loop (HITL) Manual Remediation Drawer resolution.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_dashboard_static_index_html(self):
        """Test GET / returns 200 OK and serves index.html."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("AEGIS-SRE // Mission Control Dashboard", resp.text)
        self.assertIn("HUMAN ESCALATION & REMEDIATION CONTROL", resp.text)

    def test_chaos_trigger_oom_memory_leak(self):
        """Test POST /api/v1/chaos/trigger for OOM memory leak."""
        payload = {
            "pod_name": "aegis-storefront-prod-1",
            "chaos_type": "oom"
        }
        resp = self.client.post("/api/v1/chaos/trigger", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["event"], "CHAOS_TRIGGERED")
        self.assertEqual(data["decision"]["final_action"], "RESTART_POD")
        self.assertTrue(data["decision"]["approved"])

    def test_chaos_trigger_t1059_shell_attack(self):
        """Test POST /api/v1/chaos/trigger for Falco eBPF reverse shell attack."""
        payload = {
            "pod_name": "aegis-storefront-prod-1",
            "chaos_type": "t1059_shell"
        }
        resp = self.client.post("/api/v1/chaos/trigger", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["event"], "CHAOS_TRIGGERED")
        self.assertEqual(data["decision"]["final_action"], "CILIUM_QUARANTINE_EBPF")

    def test_manual_hitl_escalation_resolution(self):
        """Test POST /api/v1/escalation/resolve for manual human operator dispatch."""
        payload = {
            "incident_id": "INC-TEST-1001",
            "target_pod": "aegis-storefront-prod-1",
            "action": "UNQUARANTINE_POD",
            "notes": "Human operator verified attack mitigated. Removing eBPF network cage."
        }
        resp = self.client.post("/api/v1/escalation/resolve", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertIn("UNQUARANTINE_POD", data["message"])

    def test_get_forensics_snapshot_api(self):
        """Test GET /api/v1/forensics/{pod_name} endpoint."""
        resp = self.client.get("/api/v1/forensics/aegis-storefront-prod-1")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["target_pod"], "aegis-storefront-prod-1")
        self.assertIn("simulated_process_tree", data)

if __name__ == "__main__":
    unittest.main()
