"""WiFiKey 单元测试（仅使用标准库 unittest，不依赖真实 WiFi 环境）。"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wifikey.audit import assess_password, audit_networks
from wifikey.exporters import to_csv, to_html, to_json, wifi_qr_payload
from wifikey.models import WifiNetwork
from wifikey.providers.linux import parse_nm_keyfile, parse_nmcli_connection_names, parse_wpa_supplicant
from wifikey.providers.macos import parse_airport_plist, parse_hardware_ports, parse_preferred_networks
from wifikey.providers.windows import (
    friendly_cipher,
    friendly_security,
    parse_current_ssid,
    parse_profile_names,
    parse_profile_text,
    parse_profile_xml,
)
from wifikey.textutil import color_enabled, display_width, render_table, strip_ansi
from wifikey.clipboard import copy_to_clipboard

SAMPLE_XML = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>TestWifi</name>
  <SSIDConfig>
    <SSID><hex>5465737457696669</hex><name>TestWifi</name></SSID>
    <nonBroadcast>false</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>TestPass123</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"""

SAMPLE_TEXT_EN = """
Profile LuckyGlow on interface WLAN:
Applied: All User Profile
Profile information
    Version                : 1
    Type                   : Wireless LAN
    Name                   : LuckyGlow
    Control options:
        Connection mode    : Connect manually
    Connectivity settings:
        Number of SSIDs        : 1
        SSID name              : "LuckyGlow"
        Network type           : Infrastructure
        Radio type             : [ Any Radio Type ]
    Security settings
        Authentication         : WPA2-Personal
        Cipher                 : CCMP
        Security key           : Present
        Key Content            : MySecret123
"""

SAMPLE_TEXT_ZH = """
接口 WLAN 的配置文件 知4-506:

已应用到: 所有用户配置文件

配置文件信息
    用户配置文件              : 所有用户配置文件
    连接模式                  : 手动连接
    SSID 名称                 : "知4-506"
    网络类型                  : 基础结构
    无线电类型                : [任何无线电类型]
    身份验证                  : WPA2 - 个人
    密码                      : CCMP
    安全密钥                  : 存在
    关键内容                  : Test@1234
"""

SAMPLE_NM = """[connection]
id=HomeWifi
type=wifi

[wifi]
mode=infrastructure
ssid=HomeWifi

[wifi-security]
key-mgmt=wpa-psk
psk=MyHomePass123

[ipv4]
method=auto
"""

SAMPLE_WPA = """
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
network={
    ssid="Office"
    psk="OfficePass123"
    key_mgmt=WPA-PSK
    scan_ssid=1
}
network={
    ssid="FreeWiFi"
    key_mgmt=NONE
}
"""


class TestWindowsParsing(unittest.TestCase):
    def test_xml_parse(self):
        net = parse_profile_xml(SAMPLE_XML)
        self.assertIsNotNone(net)
        assert net is not None
        self.assertEqual(net.ssid, "TestWifi")
        self.assertEqual(net.password, "TestPass123")
        self.assertEqual(net.security, "WPA2-Personal")
        self.assertEqual(net.cipher, "CCMP")
        self.assertEqual(net.connection_mode, "auto")
        self.assertFalse(net.hidden)

    def test_xml_protected_key(self):
        xml = SAMPLE_XML.replace("<protected>false</protected>", "<protected>true</protected>")
        net = parse_profile_xml(xml)
        assert net is not None
        self.assertIsNone(net.password)

    def test_xml_invalid(self):
        self.assertIsNone(parse_profile_xml("not xml"))

    def test_xml_transition_prefers_wpa3(self):
        xml = SAMPLE_XML.replace(
            "<authentication>WPA2PSK</authentication>",
            "<authentication>WPA2PSK</authentication><authentication>WPA3SAE</authentication>",
        )
        net = parse_profile_xml(xml)
        assert net is not None
        self.assertEqual(net.security, "WPA3-SAE")

    def test_cipher_none(self):
        self.assertIsNone(friendly_cipher("none"))
        self.assertIsNone(friendly_cipher(None))
        self.assertEqual(friendly_cipher("AES"), "CCMP")

    def test_text_typographic_quotes(self):
        net = parse_profile_text(SAMPLE_TEXT_ZH.replace('"知4-506"', "“知4-506”"), profile_name="知4-506")
        assert net is not None
        self.assertEqual(net.ssid, "知4-506")

    def test_text_en(self):
        net = parse_profile_text(SAMPLE_TEXT_EN, profile_name="LuckyGlow")
        assert net is not None
        self.assertEqual(net.ssid, "LuckyGlow")
        self.assertEqual(net.password, "MySecret123")
        self.assertEqual(net.security, "WPA2-Personal")
        self.assertEqual(net.cipher, "CCMP")
        self.assertEqual(net.connection_mode, "manual")

    def test_text_zh(self):
        net = parse_profile_text(SAMPLE_TEXT_ZH, profile_name="知4-506")
        assert net is not None
        self.assertEqual(net.ssid, "知4-506")
        self.assertEqual(net.password, "Test@1234")
        self.assertEqual(net.security, "WPA2-Personal")
        self.assertEqual(net.cipher, "CCMP")
        self.assertEqual(net.connection_mode, "manual")

    def test_text_without_password(self):
        output = SAMPLE_TEXT_EN.replace("        Key Content            : MySecret123\n", "")
        net = parse_profile_text(output, profile_name="LuckyGlow")
        assert net is not None
        self.assertIsNone(net.password)

    def test_profile_names(self):
        output = """
Profiles on interface WLAN:

User profiles
-------------
    All User Profile     : Home
    All User Profile     : Cafe 2
        All User Profile     : <None>
"""
        self.assertEqual(parse_profile_names(output), ["Home", "Cafe 2"])

        zh = """
WLAN 接口上的配置文件:

用户配置文件
-------------
    所有用户配置文件 : 家里
    所有用户配置文件 : 公司
"""
        self.assertEqual(parse_profile_names(zh), ["家里", "公司"])

    def test_current_ssid(self):
        output = """
    Name                   : WLAN
    State                  : connected
    SSID                   : LuckyGlow
    BSSID                  : 00:11:22:33:44:55
"""
        self.assertEqual(parse_current_ssid(output), "LuckyGlow")

    def test_friendly_security(self):
        self.assertEqual(friendly_security("WPA2PSK", has_key=True), "WPA2-Personal")
        self.assertEqual(friendly_security("WPA2PSK", use_onex=True), "WPA2-Enterprise")
        self.assertEqual(friendly_security("WPA3SAE"), "WPA3-SAE")
        self.assertEqual(friendly_security("WEP"), "WEP")
        self.assertEqual(friendly_security("open"), "Open")
        self.assertEqual(friendly_security("WPAPSK"), "WPA-Personal")


class TestLinuxParsing(unittest.TestCase):
    def test_nm_keyfile(self):
        net = parse_nm_keyfile(SAMPLE_NM)
        assert net is not None
        self.assertEqual(net.ssid, "HomeWifi")
        self.assertEqual(net.password, "MyHomePass123")
        self.assertEqual(net.security, "WPA-Personal")

    def test_nm_open(self):
        net = parse_nm_keyfile("[wifi]\nssid=Free\n[wifi-security]\nkey-mgmt=none\n")
        assert net is not None
        self.assertEqual(net.security, "Open")
        self.assertIsNone(net.password)

    def test_nm_sae(self):
        net = parse_nm_keyfile("[wifi]\nssid=New\n[wifi-security]\nkey-mgmt=sae\npsk=abcdef123\n")
        assert net is not None
        self.assertEqual(net.security, "WPA3-SAE")

    def test_nm_psk_flags(self):
        net = parse_nm_keyfile("[wifi]\nssid=Agent\n[wifi-security]\nkey-mgmt=wpa-psk\npsk=\npsk-flags=1\n")
        assert net is not None
        self.assertIsNone(net.password)

    def test_nm_no_ssid(self):
        self.assertIsNone(parse_nm_keyfile("[connection]\nid=x\n"))

    def test_wpa_supplicant(self):
        networks = parse_wpa_supplicant(SAMPLE_WPA)
        self.assertEqual(len(networks), 2)
        office = networks[0]
        self.assertEqual(office.ssid, "Office")
        self.assertEqual(office.password, "OfficePass123")
        self.assertEqual(office.security, "WPA-Personal")
        self.assertTrue(office.hidden)
        self.assertEqual(networks[1].security, "Open")
        self.assertIsNone(networks[1].password)

    def test_nmcli_names(self):
        output = "Home:802-11-wireless\nEth:802-3-ethernet\nWork\\:Wifi:802-11-wireless\n"
        self.assertEqual(parse_nmcli_connection_names(output), ["Home", "Work:Wifi"])


class TestMacParsing(unittest.TestCase):
    def test_hardware_ports(self):
        text = """
Hardware Port: Thunderbolt 1/0
Device: en1
Ethernet Address: aa

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: bb
"""
        self.assertEqual(parse_hardware_ports(text), "en0")

    def test_preferred_networks(self):
        text = """
Preferred networks on en0:

    HomeWifi
    Cafe 2

"""
        self.assertEqual(parse_preferred_networks(text), ["HomeWifi", "Cafe 2"])

    def test_plist(self):
        payload = json.dumps(
            {
                "KnownNetworks": {
                    "SSID_abc": {"SSID": "HomeWifi", "SecurityType": "WPA2 Personal"},
                    "SSID_def": {"SSID": "Old", "SecurityType": "WEP"},
                }
            }
        )
        result = parse_airport_plist(payload)
        self.assertEqual(result.get("HomeWifi"), "WPA2-Personal")
        self.assertEqual(result.get("Old"), "WEP")

    def test_plist_invalid(self):
        self.assertEqual(parse_airport_plist("not json"), {})


class TestAudit(unittest.TestCase):
    def test_strong_password(self):
        result = assess_password("Xk9#mQ2$vL7!zR4")
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.grade, "强")

    def test_common_password(self):
        result = assess_password("12345678")
        self.assertLess(result.score, 20)
        self.assertIn("常见弱口令", result.issues)

    def test_short_digits(self):
        result = assess_password("123456")
        self.assertLess(result.score, 35)
        self.assertIn("纯数字密码", result.issues)

    def test_empty_password(self):
        result = assess_password(None)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.grade, "无密码")

    def test_open_network_critical(self):
        networks = [WifiNetwork(ssid="Free", security="Open", password=None)]
        report = audit_networks(networks)
        codes = {f.code for f in report.findings}
        self.assertIn("open_network", codes)
        self.assertLess(report.score, 100)

    def test_reused_password(self):
        networks = [
            WifiNetwork(ssid="A", security="WPA2-Personal", password="SamePass123"),
            WifiNetwork(ssid="B", security="WPA2-Personal", password="SamePass123"),
        ]
        report = audit_networks(networks)
        reused = [f for f in report.findings if f.code == "reused_password"]
        self.assertEqual(len(reused), 2)
        self.assertEqual(len(report.stats["reused_groups"]), 1)

    def test_enterprise_no_password(self):
        networks = [WifiNetwork(ssid="Corp", security="WPA2-Enterprise")]
        report = audit_networks(networks)
        self.assertIn("enterprise_network", {f.code for f in report.findings})
        self.assertNotIn("no_password", {f.code for f in report.findings})

    def test_score_bounds(self):
        networks = [
            WifiNetwork(ssid="W1", security="WEP", password="12345"),
            WifiNetwork(ssid="W2", security="Open"),
            WifiNetwork(ssid="W3", security="WPA2-Personal", password="12345678"),
        ]
        report = audit_networks(networks)
        self.assertGreaterEqual(report.score, 0)
        self.assertLessEqual(report.score, 100)


class TestExporters(unittest.TestCase):
    def setUp(self):
        self.networks = [
            WifiNetwork(ssid="Home", password="Secret123", security="WPA2-Personal", cipher="CCMP"),
            WifiNetwork(ssid="Free", security="Open"),
        ]

    def test_json_masked(self):
        data = json.loads(to_json(self.networks, reveal=False))
        self.assertEqual(data["networks"][0]["password"], "••••••••")
        self.assertNotIn("Secret123", json.dumps(data, ensure_ascii=False))

    def test_json_reveal(self):
        data = json.loads(to_json(self.networks, reveal=True))
        self.assertEqual(data["networks"][0]["password"], "Secret123")
        self.assertEqual(data["audit"]["stats"]["total"], 2)

    def test_csv(self):
        content = to_csv(self.networks, reveal=False)
        self.assertIn("ssid,security", content)
        self.assertIn("Home", content)
        self.assertNotIn("Secret123", content)

    def test_html_masked_no_leak(self):
        html = to_html(self.networks, reveal=False)
        self.assertIn("<table>", html)
        self.assertNotIn("Secret123", html)
        self.assertIn("••••••••", html)
        self.assertIn('"canReveal": false', html)

    def test_html_reveal(self):
        html = to_html(self.networks, reveal=True)
        self.assertIn("Secret123", html)
        self.assertIn('"canReveal": true', html)

    def test_qr_payload_escaping(self):
        net = WifiNetwork(ssid="Cafe;Bar", password="Pa:ss;word", security="WPA2-Personal")
        payload = wifi_qr_payload(net)
        self.assertTrue(payload.startswith("WIFI:T:WPA;S:Cafe\\;Bar;P:Pa\\:ss\\;word;"))
        self.assertEqual(wifi_qr_payload(WifiNetwork(ssid="Free", security="Open")), "WIFI:T:nopass;S:Free;;")

    def test_qr_hidden(self):
        net = WifiNetwork(ssid="Hidden", password="Pwd12345", security="WPA2-Personal", hidden=True)
        self.assertIn("H:true;", wifi_qr_payload(net))


class TestTextUtil(unittest.TestCase):
    def test_display_width(self):
        self.assertEqual(display_width("abc"), 3)
        self.assertEqual(display_width("中文"), 4)
        self.assertEqual(display_width("\033[31m红色\033[0m"), 4)

    def test_render_table_aligns(self):
        table = render_table(["名称", "值"], [["中文", "1"], ["ab", "22"]])
        lines = table.splitlines()
        self.assertEqual(len(lines), 6)
        widths = {display_width(line) for line in lines}
        self.assertEqual(len(widths), 1)

    def test_strip_ansi(self):
        self.assertEqual(strip_ansi("\033[1m标题\033[0m"), "标题")
        self.assertEqual(strip_ansi("\033[32m★ 已保存\033[0m"), "★ 已保存")
        self.assertEqual(strip_ansi("无颜色"), "无颜色")

    def test_color_disabled_when_force_color_is_zero(self):
        # FORCE_COLOR=0 视为关闭颜色（GUI 等场景不会注入 ANSI 码）
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"FORCE_COLOR": "0"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            self.assertFalse(color_enabled())


class TestClipboard(unittest.TestCase):
    def test_copy_optional(self):
        # 不强制要求剪贴板可用，仅确保不会抛出异常
        self.assertIsInstance(copy_to_clipboard("wifikey-test"), bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
