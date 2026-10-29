"""周围网络扫描的单元测试（仅标准库，不依赖真实无线环境）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wifikey.models import ScanNetwork, WifiNetwork
from wifikey.scanner import (
    band_of_channel,
    normalize_security,
    parse_airport_scan,
    parse_netsh_networks,
    parse_nmcli_scan,
    parse_system_profiler_json,
    parse_system_profiler_text,
    rssi_to_percent,
    scan_environment,
)
from wifikey.terminal import render_scan_summary, render_scan_table

# --------------------------------------------------------------------------- 样例数据

NETSH_EN = """
Interface name : Wi-Fi
There are 5 networks currently visible.

SSID 1 : HomeNet_5G
    Network type            : Infrastructure
    Authentication          : WPA3-SAE
    Encryption              : GCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 99%
         Radio type         : 802.11ax
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 76%
         Radio type         : 802.11ax
         Channel            : 40
         Basic rates (Mbps) : 6 12 24

SSID 2 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:03
         Signal             : 92%
         Radio type         : 802.11n
         Channel            : 6

SSID 3 :
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : TKIP
    BSSID 1                 : aa:bb:cc:dd:ee:04
         Signal             : 45%
         Radio type         : 802.11g
         Channel            : 11

SSID 4 : FreeCafe
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:05
         Signal             : 60%
         Radio type         : 802.11n
         Channel            : 3

SSID 5 : OldRouter
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : WEP
    BSSID 1                 : aa:bb:cc:dd:ee:06
         Signal             : 30%
         Radio type         : 802.11b
         Channel            : 9
"""

NETSH_ZH = """
接口名称 : Wi-Fi
当前有 3 个网络可见。

SSID 1 : 我的家里WiFi
    网络类型                : 结构
    身份验证                : WPA2-Personal
    加密                    : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:f1
         信号               : 88%
         无线电类型         : 802.11n
         波段               : 2.4 GHz
         频道               : 6
         基本速率(Mbps)     : 1 2
         其他速率(Mbps)     : 5.5 11

SSID 2 : 咖啡厅免费网络
    网络类型                : 结构
    身份验证                : 开放
    加密                    : 无
    BSSID 1                 : aa:bb:cc:dd:ee:f2
         信号               : 52%
         无线电类型         : 802.11n
         信道               : 1

SSID 3 :
    网络类型                : 结构
    身份验证                : WPA2-Personal
    加密                    : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:f3
         信号               : 41%
         无线电类型         : 802.11ac
         信道               : 149
"""

NMCLI_OUT = """HomeNet:aa\\:bb\\:cc\\:dd\\:ee\\:01:88:6:2437 MHz:WPA2
Cafe5G:11\\:22\\:33\\:44\\:55\\:66:72:36:5180 MHz:WPA2 WPA3
:aa\\:bb\\:cc\\:dd\\:ee\\:03:55:11:2462 MHz:WPA1 WPA2
Office8021X:aa\\:bb\\:cc\\:dd\\:ee\\:04:30:52:5260 MHz:WPA2 802.1X
"""

AIRPORT_OUT = """                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
                     MyHomeWifi aa:bb:cc:dd:ee:ff -56  6       ye CN WPA2(PSK/AES/AES)
              My Office Network 11:22:33:44:55:66 -72  149     ye CN WPA2(802.1x/AES/AES)
                          OldTKIP aa:bb:cc:dd:ee:11 -68  3       n  -- WPA(PSK/TKIP/TKIP)
"""

PROFILER_TEXT = """Wi-Fi:

      Current Network Information:
          MyWifi:
              PHY Mode: 802.11ax
              Channel: 6 (2.437GHz)
              Security: WPA2 Personal

      Other Local Wi-Fi Networks:
          Neighbor-5G:
              BSSID: aa:bb:cc:dd:ee:ff
              PHY Mode: 802.11ac
              Channel: 149 (5.745GHz)
              Security: WPA2 Personal
          OldRouter:
              BSSID: 11:22:33:44:55:66
              PHY Mode: 802.11g
              Channel: 11 (2.462GHz)
              Security: WPA2 Personal

      Bluetooth:
"""

PROFILER_JSON = """{
  "SPAirPortDataType": [
    {
      "_name": "en0",
      "spairport_airport_other_local_wireless_networks": [
        {
          "_name": "Cafe",
          "spairport_airport_network_bssid": "AA:BB:CC:DD:EE:FF",
          "spairport_airport_network_channel": "6 (2.437GHz)",
          "spairport_airport_network_security": "WPA2 Personal",
          "spairport_airport_network_signal": "45%"
        },
        {
          "_name": "OpenGuest",
          "spairport_airport_network_bssid": "11:22:33:44:55:66",
          "spairport_airport_network_channel": "36 (5.18GHz)",
          "spairport_airport_network_security": "NONE"
        }
      ]
    }
  ]
}"""


# --------------------------------------------------------------------------- 基础工具


class TestBasics(unittest.TestCase):
    def test_band_of_channel(self):
        self.assertEqual(band_of_channel(6), "2.4 GHz")
        self.assertEqual(band_of_channel(13), "2.4 GHz")
        self.assertEqual(band_of_channel(36), "5 GHz")
        self.assertEqual(band_of_channel(149), "5 GHz")
        self.assertEqual(band_of_channel(1, 2437), "2.4 GHz")
        self.assertEqual(band_of_channel(37, 5955), "6 GHz")
        self.assertEqual(band_of_channel(None), "")

    def test_rssi_to_percent(self):
        self.assertEqual(rssi_to_percent(-50), 100)
        self.assertEqual(rssi_to_percent(-100), 0)
        self.assertEqual(rssi_to_percent(-75), 50)
        self.assertEqual(rssi_to_percent(-30), 100)  # 上限截断

    def test_normalize_security(self):
        cases = {
            "": "Open",
            "none": "Open",
            "None": "Open",
            "WEP": "WEP",
            "WPA2": "WPA2-Personal",
            "WPA2-Personal": "WPA2-Personal",
            "WPA2 Personal": "WPA2-Personal",
            "WPA2(PSK/AES/AES)": "WPA2-Personal",
            "WPA2 Enterprise": "WPA2-Enterprise",
            "WPA2 802.1X": "WPA2-Enterprise",
            "WPA(802.1x/TKIP/AES)": "WPA-Enterprise",
            "WPA1 WPA2": "WPA1/WPA2 (过渡)",
            "WPA2 WPA3": "WPA2/WPA3 (过渡)",
            "WPA3": "WPA3-Personal",
            "WPA3-SAE": "WPA3-SAE",
            "WPA3(SAE/AES/AES)": "WPA3-SAE",
            "OWE": "OWE (Enhanced Open)",
        }
        for raw, expected in cases.items():
            self.assertEqual(normalize_security(raw), expected, msg=raw)


# --------------------------------------------------------------------------- Windows


class TestNetshScan(unittest.TestCase):
    def setUp(self):
        self.nets = parse_netsh_networks(NETSH_EN)

    def test_count_and_sort(self):
        # 5 个 SSID：HomeNet_5G 同频段双 BSSID 合并为 1 行；隐藏网络 1 行
        self.assertEqual(len(self.nets), 5)
        self.assertEqual(self.nets[0].ssid, "HomeNet_5G")  # 按信号降序

    def test_multi_bssid_aggregation(self):
        net = next(n for n in self.nets if n.ssid == "HomeNet_5G")
        self.assertEqual(net.bssid_count, 2)
        self.assertEqual(net.signal, 99)
        self.assertEqual(net.channel, 36)
        self.assertEqual(net.band, "5 GHz")
        self.assertEqual(net.security, "WPA3-SAE")

    def test_hidden_network(self):
        hidden = [n for n in self.nets if not n.ssid]
        self.assertEqual(len(hidden), 1)
        self.assertEqual(hidden[0].channel, 11)
        self.assertTrue(hidden[0].uses_tkip)

    def test_open_and_wep(self):
        cafe = next(n for n in self.nets if n.ssid == "FreeCafe")
        self.assertTrue(cafe.is_open)
        self.assertFalse(cafe.is_legacy)
        old = next(n for n in self.nets if n.ssid == "OldRouter")
        self.assertTrue(old.is_wep)
        self.assertTrue(old.is_legacy)

    def test_chinese_labels(self):
        nets = parse_netsh_networks(NETSH_ZH)
        self.assertEqual(len(nets), 3)
        home = next(n for n in nets if n.ssid == "我的家里WiFi")
        self.assertEqual(home.security, "WPA2-Personal")
        self.assertEqual(home.signal, 88)
        self.assertEqual(home.channel, 6)  # 标签为“频道”（Win11 中文）/“信道”（旧版）
        self.assertEqual(home.band, "2.4 GHz")  # 标签为“波段”
        cafe = next(n for n in nets if n.ssid == "咖啡厅免费网络")
        self.assertTrue(cafe.is_open)
        hidden = next(n for n in nets if not n.ssid)
        self.assertEqual(hidden.channel, 149)
        self.assertEqual(hidden.band, "5 GHz")


# --------------------------------------------------------------------------- Linux / macOS


class TestNmcliScan(unittest.TestCase):
    def setUp(self):
        self.nets = parse_nmcli_scan(NMCLI_OUT)

    def test_fields(self):
        home = next(n for n in self.nets if n.ssid == "HomeNet")
        self.assertEqual(home.bssid, "aa:bb:cc:dd:ee:01")
        self.assertEqual(home.signal, 88)
        self.assertEqual(home.channel, 6)
        self.assertEqual(home.band, "2.4 GHz")
        self.assertEqual(home.security, "WPA2-Personal")

    def test_transition_and_enterprise(self):
        cafe = next(n for n in self.nets if n.ssid == "Cafe5G")
        self.assertTrue(cafe.is_wpa3)
        self.assertEqual(cafe.band, "5 GHz")
        office = next(n for n in self.nets if n.ssid == "Office8021X")
        self.assertEqual(office.security, "WPA2-Enterprise")

    def test_hidden_ssid_with_legacy_security(self):
        hidden = next(n for n in self.nets if not n.ssid)
        self.assertEqual(hidden.security, "WPA1/WPA2 (过渡)")
        self.assertTrue(hidden.is_legacy)


class TestAirportScan(unittest.TestCase):
    def setUp(self):
        self.nets = parse_airport_scan(AIRPORT_OUT)

    def test_ssid_with_spaces(self):
        office = next(n for n in self.nets if n.ssid == "My Office Network")
        self.assertEqual(office.security, "WPA2-Enterprise")
        self.assertEqual(office.channel, 149)

    def test_rssi_and_cipher(self):
        home = next(n for n in self.nets if n.ssid == "MyHomeWifi")
        self.assertEqual(home.signal, 88)  # -56 dBm → 88%
        self.assertEqual(home.cipher, "CCMP")
        tkip = next(n for n in self.nets if n.ssid == "OldTKIP")
        self.assertTrue(tkip.uses_tkip)
        self.assertTrue(tkip.is_legacy)


class TestSystemProfiler(unittest.TestCase):
    def test_text_parser(self):
        nets = parse_system_profiler_text(PROFILER_TEXT)
        names = [n.ssid for n in nets]
        self.assertIn("Neighbor-5G", names)
        self.assertIn("OldRouter", names)
        self.assertNotIn("MyWifi", names)  # 当前网络不在 Other 列表
        neighbor = next(n for n in nets if n.ssid == "Neighbor-5G")
        self.assertEqual(neighbor.band, "5 GHz")
        self.assertEqual(neighbor.bssid, "aa:bb:cc:dd:ee:ff")

    def test_json_parser(self):
        nets = parse_system_profiler_json(PROFILER_JSON)
        self.assertEqual(len(nets), 2)
        cafe = next(n for n in nets if n.ssid == "Cafe")
        self.assertEqual(cafe.signal, 45)
        self.assertEqual(cafe.security, "WPA2-Personal")
        guest = next(n for n in nets if n.ssid == "OpenGuest")
        self.assertTrue(guest.is_open)
        self.assertEqual(guest.band, "5 GHz")


# --------------------------------------------------------------------------- 环境评估


class TestScanEnvironment(unittest.TestCase):
    def test_spoof_detection(self):
        saved = [WifiNetwork(ssid="HomeNet", password="xxx", security="WPA2-Personal")]
        scanned = [
            ScanNetwork(ssid="HomeNet", security="Open", signal=88),
            ScanNetwork(ssid="Other", security="WPA2-Personal", signal=70),
        ]
        summary = scan_environment(scanned, saved)
        codes = [f.code for f in summary.findings]
        self.assertIn("scan_spoof", codes)
        spoof = next(f for f in summary.findings if f.code == "scan_spoof")
        self.assertEqual(spoof.severity, "high")
        self.assertEqual(spoof.ssid, "HomeNet")

    def test_no_spoof_for_matching_security(self):
        saved = [WifiNetwork(ssid="HomeNet", password="xxx", security="WPA2-Personal")]
        scanned = [ScanNetwork(ssid="HomeNet", security="WPA2-Personal", signal=88, saved=True)]
        summary = scan_environment(scanned, saved)
        self.assertNotIn("scan_spoof", [f.code for f in summary.findings])

    def test_stats(self):
        scanned = [
            ScanNetwork(ssid="A", security="Open", channel=6, band="2.4 GHz", signal=80),
            ScanNetwork(ssid="B", security="WEP", channel=7, band="2.4 GHz", signal=70),
            ScanNetwork(ssid="C", security="WPA3-SAE", channel=36, band="5 GHz", signal=60, saved=True),
            ScanNetwork(ssid="D", security="WPA2-Personal", channel=11, band="2.4 GHz", signal=50),
            ScanNetwork(ssid="E", security="WPA2-Personal", channel=12, band="2.4 GHz", signal=40),
        ]
        summary = scan_environment(scanned, [])
        self.assertEqual(summary.total, 5)
        self.assertEqual(summary.open_count, 1)
        self.assertEqual(summary.wep_count, 1)
        self.assertEqual(summary.wpa3_count, 1)
        self.assertEqual(summary.saved_count, 1)
        self.assertEqual(summary.bands["2.4 GHz"], 4)
        self.assertEqual(summary.bands["5 GHz"], 1)
        # 2.4G 网络 A(6) B(7) D(11) E(12)：±4 视为重叠
        # 信道 1 → 0 个；信道 6 → 6、7 共 2 个；信道 11 → 7、11、12 共 3 个
        self.assertEqual(summary.overlap_24[1], 0)
        self.assertEqual(summary.overlap_24[6], 2)
        self.assertEqual(summary.overlap_24[11], 3)

    def test_saved_marking(self):
        from wifikey.scanner import _mark_saved

        nets = [ScanNetwork(ssid="Home"), ScanNetwork(ssid="Other")]
        _mark_saved(nets, {"home"})
        self.assertTrue(nets[0].saved)
        self.assertFalse(nets[1].saved)


# --------------------------------------------------------------------------- 渲染


class TestRenderScan(unittest.TestCase):
    def test_render_scan_table(self):
        nets = [
            ScanNetwork(ssid="HomeNet", signal=92, channel=6, band="2.4 GHz", security="WPA2-Personal", saved=True),
            ScanNetwork(ssid="FreeCafe", signal=60, channel=3, band="2.4 GHz", security="Open"),
        ]
        text = render_scan_table(nets)
        self.assertIn("HomeNet", text)
        self.assertIn("已保存", text)
        self.assertIn("开放", text)
        self.assertIn("92%", text)

    def test_render_scan_summary(self):
        scanned = [ScanNetwork(ssid="A", security="Open")]
        summary = scan_environment(scanned, [])
        text = render_scan_summary(summary, source="netsh", scanned_at="12:00:00")
        self.assertIn("可见网络", text)
        self.assertIn("环境观察", text)
        self.assertIn("netsh", text)


if __name__ == "__main__":
    unittest.main()
