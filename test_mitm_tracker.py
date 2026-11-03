"""Tests for the detection logic. Run with:  python -m unittest -v

Every network read and every system-changing call is faked, so these need no
Administrator rights, send no packets, and never touch the real baseline, log
file, ARP table or firewall.
"""
import contextlib
import io
import unittest
from unittest import mock

import mitm_tracker as m

BASELINE = {
    "gateway_ip": "192.168.1.1",
    "gateway_mac": "aa:aa:aa:aa:aa:01",
    "public_ip": "1.1.1.1",
    "interface": "Wi-Fi",
    "wifi_interface": "Wi-Fi",
    "ssid": "Home",
    "bssid": "bb:bb:bb:bb:bb:01",
    "wifi_profile": "Home",
    "local_ip": "192.168.1.5",
    "subnet": "192.168.1.0/24",
    "dhcp_server": "192.168.1.1",
    "dns_source": "dhcp",
    "dns_servers": "8.8.8.8",
    "checked_at": "2026-01-01T00:00:00",
}

ARP_SPOOF = {"gateway_mac": "cc:cc:cc:cc:cc:01"}
HIJACK_SAME_SUBNET = {
    "gateway_ip": "192.168.1.66",
    "gateway_mac": "cc:cc:cc:cc:cc:01",
    "dhcp_server": "192.168.1.66",
    "dns_servers": "192.168.1.66",
}
HIJACK_NEW_SUBNET = dict(HIJACK_SAME_SUBNET, gateway_ip="10.0.0.1",
                         subnet="10.0.0.0/24", dhcp_server="10.0.0.1",
                         dns_servers="10.0.0.1")
EVIL_TWIN = {"bssid": "dd:dd:dd:dd:dd:01"}
EVIL_TWIN_OWN_GATEWAY = dict(HIJACK_NEW_SUBNET, bssid="dd:dd:dd:dd:dd:01")
OTHER_WIFI = dict(HIJACK_NEW_SUBNET, ssid="Lab", bssid="dd:dd:dd:dd:dd:01",
                  public_ip="2.2.2.2")
PUBLIC_IP_ONLY = {"public_ip": "2.2.2.2"}


class Harness(unittest.TestCase):
    """Runs check() against a faked network and records what it said."""

    def setUp(self):
        self.said = []       # (message, written_to_file)
        self.alerts = []
        self.defended = []
        self.restored = []
        self.current = dict(BASELINE)

        fakes = {
            "log": lambda msg, to_file=True: self.said.append((msg, to_file)),
            "alert": lambda msg, beep=True: self.alerts.append(msg),
            "load_baseline": lambda: dict(BASELINE),
            "snapshot": lambda *a, **k: dict(self.current),
            "_report_duplicates": lambda *a, **k: None,
            "_defend_bounded": lambda *a, **k: self.defended.append(1),
            "_restore_bounded": lambda *a, **k: self.restored.append(1),
        }
        for name, fake in fakes.items():
            patcher = mock.patch.object(m, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_check(self, change, state=None, **kwargs):
        self.current = dict(BASELINE, **change)
        return m.check(True, {} if state is None else state, **kwargs)

    def text(self):
        return "\n".join(msg for msg, _ in self.said)


class Classification(Harness):
    def test_clean_network_raises_no_alert(self):
        self.assertEqual(self.run_check({}), 0)
        self.assertEqual(self.alerts, [])

    def test_arp_spoof_is_called_spoofing(self):
        self.assertEqual(self.run_check(ARP_SPOOF), 1)
        self.assertIn("ARP spoofing or a rogue router", self.text())

    def test_hijack_detected_on_same_and_new_subnet(self):
        for change in (HIJACK_SAME_SUBNET, HIJACK_NEW_SUBNET):
            self.assertTrue(m.rogue_dhcp(BASELINE, dict(BASELINE, **change)))

    def test_other_wifi_is_not_a_hijack_or_spoofing(self):
        self.assertFalse(m.rogue_dhcp(BASELINE, dict(BASELINE, **OTHER_WIFI)))
        self.run_check(OTHER_WIFI)
        self.assertNotIn("ARP spoofing or a rogue router", self.text())

    def test_public_ip_change_gives_no_go_back_advice(self):
        self.assertEqual(self.run_check(PUBLIC_IP_ONLY), 1)
        self.assertNotIn("--restore", self.text())


class AlertWording(Harness):
    def test_evil_twin_wording_when_ssid_is_unchanged(self):
        self.run_check(EVIL_TWIN)
        self.assertIn("evil twin", self.text())

    def test_no_evil_twin_claim_when_ssid_changed(self):
        self.run_check(OTHER_WIFI)
        self.assertNotIn("evil twin", self.text())
        self.assertNotIn("Same network name", self.text())

    def test_hijack_is_not_described_as_harmless(self):
        for change in (HIJACK_SAME_SUBNET, HIJACK_NEW_SUBNET):
            self.said.clear()
            self.run_check(change)
            self.assertNotIn("Expected:", self.text())
            self.assertNotIn("simply a different router", self.text())
            self.assertIn("impersonating", self.text())

    def test_evil_twin_with_own_gateway_is_not_described_as_harmless(self):
        self.run_check(EVIL_TWIN_OWN_GATEWAY)
        self.assertNotIn("Expected:", self.text())
        self.assertIn("evil twin", self.text())

    def test_other_wifi_mac_change_is_still_expected(self):
        self.run_check(OTHER_WIFI)
        self.assertIn("Expected:", self.text())

    def test_same_subnet_hijack_does_not_claim_a_different_subnet(self):
        self.run_check(HIJACK_SAME_SUBNET)
        self.assertNotIn("different subnet", self.text())

    def test_new_subnet_wording_is_kept_when_subnet_moved(self):
        self.run_check(HIJACK_NEW_SUBNET)
        self.assertIn("different subnet", self.text())


class RepeatCycles(Harness):
    def second_cycle(self, change, **kwargs):
        state = {}
        self.run_check(change, state, **kwargs)
        self.said.clear()
        self.alerts.clear()
        self.assertEqual(self.run_check(change, state, **kwargs), 1)

    def test_repeat_cycle_writes_nothing_to_the_log_file(self):
        for change in (ARP_SPOOF, HIJACK_SAME_SUBNET, OTHER_WIFI, EVIL_TWIN):
            self.second_cycle(change)
            self.assertEqual([msg for msg, to_file in self.said if to_file], [])
            self.assertEqual(self.alerts, [])

    def test_first_cycle_still_gives_the_hint(self):
        self.run_check(OTHER_WIFI)
        self.assertIn("--restore", self.text())

    def test_repeat_cycle_keeps_responding(self):
        # Quiet must only mean quiet: the countermeasures have to keep running.
        self.second_cycle(ARP_SPOOF, do_defend=True)
        self.assertEqual(len(self.defended), 2)
        self.second_cycle(OTHER_WIFI, do_restore=True)
        self.assertEqual(len(self.restored), 2)

    def test_a_new_change_alerts_again(self):
        state = {}
        self.run_check(ARP_SPOOF, state)
        self.alerts.clear()
        self.run_check(HIJACK_SAME_SUBNET, state)
        self.assertNotEqual(self.alerts, [])


class Status(unittest.TestCase):
    def status_output(self, change):
        fakes = {
            "load_baseline": lambda: dict(BASELINE),
            "snapshot": lambda *a, **k: dict(BASELINE, **change),
            "is_admin": lambda: False,
            "have_scapy": lambda: True,
            "static_neighbors": lambda: [],
            "list_blocks": lambda: [],
            "duplicate_macs": lambda: {},
        }
        patchers = [mock.patch.object(m, n, f) for n, f in fakes.items()]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            m.print_status()
        return out.getvalue()

    def test_only_own_address_changed_needs_no_restore(self):
        out = self.status_output({"local_ip": "192.168.1.77"})
        self.assertNotIn("--restore", out)
        self.assertIn("You are on the trusted network", out)
        self.assertIn("My address", out)

    def test_real_drift_still_suggests_restore(self):
        out = self.status_output({"ssid": "Lab", "local_ip": "192.168.1.77"})
        self.assertIn("--restore", out)
        self.assertNotIn("You are on the trusted network", out)

    def test_no_drift_says_trusted(self):
        self.assertIn("You are on the trusted network", self.status_output({}))


if __name__ == "__main__":
    unittest.main()
