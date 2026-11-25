"""Regression tests for internet-gated monitoring startup and shutdown."""

import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import connectivity_monitor


class ConnectivityStateTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.status_file = Path(self.temp_dir.name) / "internet_status.json"
        self.status_path_patch = mock.patch.object(
            connectivity_monitor, "STATUS_FILE", self.status_file
        )
        self.status_path_patch.start()

    def tearDown(self):
        self.status_path_patch.stop()
        self.temp_dir.cleanup()

    def test_connected_status_allows_start_and_disconnect_blocks_it(self):
        connectivity_monitor._publish_status(True, None)
        self.assertTrue(connectivity_monitor.internet_is_available())
        connectivity_monitor._publish_status(False, "DNS lookup failed")
        self.assertFalse(connectivity_monitor.internet_is_available())
        self.assertFalse(connectivity_monitor.internet_loss_confirmed())
        connectivity_monitor._publish_status(False, "Connection timed out")
        self.assertTrue(connectivity_monitor.internet_loss_confirmed())

    def test_dns_and_endpoint_failures_return_offline_without_raising(self):
        with mock.patch.object(
                connectivity_monitor.socket, "create_connection",
                side_effect=OSError("name resolution or connect timeout")):
            connected, error = connectivity_monitor.check_internet_connection()
        self.assertFalse(connected)
        self.assertIn("www.microsoft.com", error)
        self.assertIn("www.cloudflare.com", error)

    def test_controller_refuses_start_while_disconnected(self):
        import agent_controller

        with mock.patch.object(agent_controller, "internet_is_available", return_value=False), \
                mock.patch.object(agent_controller.subprocess, "Popen") as popen:
            started, message = agent_controller.start_agent()
        self.assertFalse(started)
        self.assertEqual(
            message, "Internet connection required. Monitoring cannot be started."
        )
        popen.assert_not_called()


class SupervisorConnectivityTests(unittest.TestCase):
    def test_worker_refuses_to_start_engines_when_disconnected(self):
        temp_dir = tempfile.TemporaryDirectory()
        fake_paths = SimpleNamespace(
            agent_stop_request=Path(temp_dir.name) / "stop.request",
            agent_status=Path(temp_dir.name) / "agent_status.json",
        )
        monitor_stub = SimpleNamespace(monitor_loop=None)
        network_stub = SimpleNamespace(
            get_network_monitor_status=None,
            start_network_monitor=None,
            stop_network_monitor=None,
        )
        with mock.patch.dict("sys.modules", {
                "monitor_engine": monitor_stub,
                "network_monitor": network_stub,
        }):
            import agent_runtime
        agent_runtime.stop_event.clear()
        with mock.patch.object(agent_runtime, "APP_PATHS", fake_paths), \
                mock.patch.object(agent_runtime, "internet_is_available", return_value=False), \
                mock.patch.object(agent_runtime, "monitor_loop") as process_loop, \
                mock.patch.object(agent_runtime, "start_network_monitor") as network_start:
            agent_runtime.run_agent()
        process_loop.assert_not_called()
        network_start.assert_not_called()
        temp_dir.cleanup()

    def _run_supervisor(self, connectivity):
        temp_dir = tempfile.TemporaryDirectory()
        stop_request = Path(temp_dir.name) / "stop.request"
        fake_paths = SimpleNamespace(
            agent_stop_request=stop_request,
            agent_status=Path(temp_dir.name) / "agent_status.json",
        )
        events = []

        def process_loop(stop_event, on_cycle=None):
            events.append("process_started")
            stop_event.wait(2)

        monitor_stub = SimpleNamespace(monitor_loop=None)
        network_stub = SimpleNamespace(
            get_network_monitor_status=None,
            start_network_monitor=None,
            stop_network_monitor=None,
        )
        with mock.patch.dict("sys.modules", {
                "monitor_engine": monitor_stub,
                "network_monitor": network_stub,
        }):
            import agent_runtime
        agent_runtime.stop_event.clear()

        real_publish_status = agent_runtime.publish_status

        def publish_then_stop(*args, **kwargs):
            real_publish_status(*args, **kwargs)
            if kwargs.get("final_status") is None:
                agent_runtime.stop_event.set()

        with mock.patch.object(agent_runtime, "APP_PATHS", fake_paths), \
                mock.patch.object(agent_runtime, "internet_is_available", return_value=True), \
                mock.patch.object(agent_runtime, "get_internet_status", return_value=connectivity), \
                mock.patch.object(agent_runtime, "monitor_loop", side_effect=process_loop), \
                mock.patch.object(agent_runtime, "publish_status", side_effect=publish_then_stop), \
                mock.patch.object(agent_runtime, "start_network_monitor", side_effect=lambda: (events.append("network_started") or True, "started")), \
                mock.patch.object(agent_runtime, "get_network_monitor_status", return_value={"running": True}), \
                mock.patch.object(agent_runtime, "stop_network_monitor", side_effect=lambda: events.append("network_stopped")):
            agent_runtime.run_agent()
        temp_dir.cleanup()
        return events

    def test_disconnect_stops_both_engines_and_reconnect_does_not_restart(self):
        events = self._run_supervisor({
            "status": "OFFLINE", "fresh": True, "connected": False,
            "offline_confirmed": True, "error": "Connection timed out",
        })
        self.assertIn("process_started", events)
        self.assertIn("network_started", events)
        self.assertIn("network_stopped", events)
        self.assertEqual(events.count("process_started"), 1)
        self.assertEqual(events.count("network_started"), 1)

    def test_manual_start_after_reconnection_starts_both_engines(self):
        events = self._run_supervisor({
            "status": "ONLINE", "fresh": True, "connected": True,
            "offline_confirmed": False, "error": None,
        })
        self.assertIn("process_started", events)
        self.assertIn("network_started", events)
        # The online supervisor is explicitly stopped by the test after its
        # initial publication; reconnection alone never creates this run.
        self.assertEqual(events.count("process_started"), 1)
        self.assertEqual(events.count("network_started"), 1)


if __name__ == "__main__":
    unittest.main()
