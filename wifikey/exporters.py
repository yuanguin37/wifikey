"""导出为 JSON / CSV / TXT / HTML，以及 WiFi 二维码。"""

from __future__ import annotations

import csv
import io
import json
import sys
from datetime import datetime
from pathlib import Path

from wifikey import __version__
from wifikey.audit import assess_password, audit_networks
from wifikey.models import MASK, WifiNetwork
from wifikey.textutil import render_table

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}


def mask_password(password: str | None) -> str:
    return MASK if password else "—"


def _meta(platform: str | None = None) -> dict:
    return {
        "tool": "wifikey",
        "version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "platform": platform or sys.platform,
    }


def build_rows(networks: list[WifiNetwork], reveal: bool = True) -> list[dict]:
    """生成带评估结果的扁平行数据，供 CSV / HTML / JSON 复用。"""
    report = audit_networks(networks)
    findings_by_ssid: dict[str, list] = {}
    for finding in report.findings:
        findings_by_ssid.setdefault(finding.ssid, []).append(finding)

    rows = []
    for net in networks:
        assessment = assess_password(net.password)
        related = findings_by_ssid.get(net.ssid, [])
        risk = related[0].severity if related else ""
        rows.append(
            {
                "ssid": net.ssid,
                "security": net.security,
                "cipher": net.cipher or "—",
                "password": net.password if reveal else (MASK if net.password else ""),
                "has_password": net.has_password,
                "hidden": net.hidden,
                "connection_mode": net.connection_mode or "—",
                "source": net.source,
                "score": assessment.score if net.password else 0,
                "grade": assessment.grade if net.password else "无密码",
                "issues": assessment.issues,
                "risk": risk,
                "risk_label": SEVERITY_LABEL.get(risk, ""),
                "findings": [
                    {"title": f.title, "severity": f.severity, "detail": f.detail} for f in related
                ],
            }
        )
    return rows


def to_json(networks: list[WifiNetwork], reveal: bool = True, platform: str | None = None) -> str:
    report = audit_networks(networks)
    clean_stats = {k: v for k, v in report.stats.items() if k != "assessments"}
    payload = {
        **_meta(platform),
        "audit": {
            "score": report.score,
            "stats": clean_stats,
            "findings": [
                {"ssid": f.ssid, "code": f.code, "severity": f.severity, "title": f.title, "detail": f.detail}
                for f in report.findings
            ],
        },
        "networks": [n.to_dict(reveal=reveal) for n in networks],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_csv(networks: list[WifiNetwork], reveal: bool = True) -> str:
    rows = build_rows(networks, reveal)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        ["ssid", "security", "cipher", "password", "has_password", "strength", "score", "issues", "hidden", "connection_mode", "source"]
    )
    for row in rows:
        writer.writerow(
            [
                row["ssid"],
                row["security"],
                row["cipher"],
                row["password"] or "",
                "yes" if row["has_password"] else "no",
                row["grade"],
                row["score"],
                "；".join(row["issues"]),
                "yes" if row["hidden"] else "no",
                row["connection_mode"],
                row["source"],
            ]
        )
    return buffer.getvalue()


def to_txt(networks: list[WifiNetwork], reveal: bool = True, platform: str | None = None) -> str:
    rows = build_rows(networks, reveal)
    table = [[
        str(i + 1),
        row["ssid"],
        row["security"],
        row["cipher"],
        row["password"] if row["password"] else "—",
        f"{row['grade']}({row['score']})" if row["has_password"] else "—",
        row["risk_label"] or "—",
    ] for i, row in enumerate(rows)]
    meta = _meta(platform)
    report = audit_networks(networks)
    lines = [
        "=" * 66,
        "WiFiKey · 已保存 WiFi 密码与安全审计报告",
        "=" * 66,
        f"生成时间 : {meta['generated_at']}",
        f"运行平台 : {meta['platform']}",
        f"网络数量 : {len(networks)}",
        f"整体评分 : {report.score} / 100",
        "",
        render_table(
            ["#", "SSID", "安全类型", "加密", "密码", "强度", "风险"],
            table,
            aligns=["right", "left", "left", "left", "left", "left", "left"],
            max_widths=[4, 28, 20, 10, 32, 12, 8],
        ),
        "",
        "风险汇总:",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(
                f"  [{SEVERITY_LABEL[finding.severity]}] {finding.title} · {finding.ssid}"
                + (f" — {finding.detail}" if finding.detail else "")
            )
    else:
        lines.append("  未发现明显风险。")
    lines += ["", "提示: 本文件包含明文密码，请勿上传网盘或公开发布。", ""]
    return "\n".join(lines)


def wifi_qr_payload(net: WifiNetwork) -> str:
    """生成标准 WIFI: 二维码内容。"""
    def esc(value: str) -> str:
        return "".join("\\" + ch if ch in "\\;,:\"" else ch for ch in value)

    auth = "nopass"
    if net.is_open:
        auth = "nopass"
    elif "WEP" in net.security.upper():
        auth = "WEP"
    elif net.is_wpa1_only:
        auth = "WPA"
    else:
        auth = "WPA"
    payload = f"WIFI:T:{auth};S:{esc(net.ssid)};"
    if not net.is_open and net.password:
        payload += f"P:{esc(net.password)};"
    if net.hidden:
        payload += "H:true;"
    return payload + ";"


def _import_qrcode():
    try:
        import qrcode  # type: ignore

        return qrcode
    except ImportError:
        return None


def render_qr_ascii(payload: str) -> str | None:
    """在终端用半角方块绘制二维码；缺少 qrcode 依赖时返回 None。"""
    qrcode = _import_qrcode()
    if qrcode is None:
        return None
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(payload)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    lines = []
    for y in range(0, len(matrix), 2):
        top = matrix[y]
        bottom = matrix[y + 1] if y + 1 < len(matrix) else [False] * len(top)
        line = []
        for x, dark_top in enumerate(top):
            dark_bottom = bottom[x]
            if dark_top and dark_bottom:
                line.append("█")
            elif dark_top:
                line.append("▀")
            elif dark_bottom:
                line.append("▄")
            else:
                line.append(" ")
        lines.append("".join(line))
    return "\n".join(lines)


def save_qr_image(payload: str, path: str | Path) -> tuple[bool, str]:
    """保存二维码图片（PNG 需要 Pillow，SVG 仅依赖 qrcode）。"""
    qrcode = _import_qrcode()
    if qrcode is None:
        return False, "未安装 qrcode 依赖，请先执行: pip install qrcode"
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix.lower() == ".svg":
        import qrcode.image.svg  # type: ignore

        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(payload, image_factory=factory, border=2)
        img.save(target)
        return True, str(target)
    try:
        import qrcode.image.pil  # type: ignore  # noqa: F401

        img = qrcode.make(payload, border=2)
        img.save(target)
        return True, str(target)
    except Exception:
        svg_path = target.with_suffix(".svg")
        import qrcode.image.svg  # type: ignore

        img = qrcode.make(payload, image_factory=qrcode.image.svg.SvgPathImage, border=2)
        img.save(svg_path)
        return True, f"{svg_path}（未安装 Pillow，已改为 SVG）"


_HTML_STYLE = """
:root{
  --bg:#070b16;--card:#111a2e;--card2:#0d1526;--line:#22304d;
  --text:#e8eef9;--muted:#91a4c2;--accent:#2dd4bf;--accent2:#60a5fa;
  --crit:#f87171;--high:#fbbf24;--med:#60a5fa;--low:#94a3b8;--ok:#34d399;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 10% -10%,#16305c 0%,transparent 60%),
radial-gradient(900px 500px at 100% 0%,#0e4b48 0%,transparent 55%),var(--bg);
color:var(--text);font-family:"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;line-height:1.5}
.page{max-width:1180px;margin:0 auto;padding:36px 24px 64px}
.hero{background:linear-gradient(145deg,#111c33,#0b1324);border:1px solid var(--line);border-radius:20px;padding:28px 30px;box-shadow:0 24px 60px rgba(0,0,0,.35)}
.brandrow{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.5px;color:var(--accent);font-size:15px}
.brand svg{width:22px;height:22px}
.ts{color:var(--muted);font-size:13px}
h1{margin:16px 0 6px;font-size:30px;letter-spacing:.5px}
.sub{color:var(--muted);margin:0 0 22px;font-size:14px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.stat{background:linear-gradient(160deg,rgba(45,212,191,.10),rgba(96,165,250,.06));border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.stat .k{font-size:12px;color:var(--muted);letter-spacing:.6px}
.stat .v{font-size:26px;font-weight:700;margin-top:6px}
.stat .v small{font-size:12px;color:var(--muted);font-weight:400;margin-left:4px}
.scorebar{height:8px;border-radius:99px;background:rgba(255,255,255,.08);margin-top:10px;overflow:hidden}
.scorebar>span{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:26px 0 14px}
input[type=search],select{background:var(--card2);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:9px 12px;font-size:14px;outline:none;min-width:180px}
input[type=search]:focus,select:focus{border-color:var(--accent)}
button{background:var(--card2);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:9px 14px;font-size:13px;cursor:pointer;transition:.18s}
button:hover{border-color:var(--accent);color:var(--accent)}
button.primary{background:linear-gradient(135deg,var(--accent),#0ea5e9);border:none;color:#04121a;font-weight:700}
hint{color:var(--muted);font-size:12px}
.table-wrap{background:var(--card);border:1px solid var(--line);border-radius:16px;overflow:auto;box-shadow:0 18px 40px rgba(0,0,0,.28)}
table{width:100%;border-collapse:collapse;font-size:14px;min-width:860px}
thead th{position:sticky;top:0;background:#101a2f;color:var(--muted);text-align:left;padding:13px 14px;font-weight:600;font-size:12.5px;letter-spacing:.5px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap}
thead th:hover{color:var(--accent)}
tbody tr{border-bottom:1px solid rgba(34,48,77,.55)}
tbody tr:hover{background:rgba(45,212,191,.05)}
td{padding:12px 14px;vertical-align:middle}
.ssid{font-weight:600}
.ssid .lock{color:var(--muted);font-size:12px;margin-left:6px}
.pwd{font-family:Consolas,"SFMono-Regular",monospace;color:#a5f3eb;word-break:break-all}
.pwd.masked{color:var(--muted);letter-spacing:2px}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11.5px;border:1px solid transparent;white-space:nowrap}
.badge.crit{color:var(--crit);border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.10)}
.badge.high{color:var(--high);border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.10)}
.badge.med{color:var(--med);border-color:rgba(96,165,250,.4);background:rgba(96,165,250,.10)}
.badge.low{color:var(--low);border-color:rgba(148,163,184,.35);background:rgba(148,163,184,.10)}
.badge.info{color:var(--accent);border-color:rgba(45,212,191,.4);background:rgba(45,212,191,.10)}
.badge.ok{color:var(--ok);border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.10)}
.strength{display:flex;align-items:center;gap:8px;min-width:118px}
.strength .bar{width:64px;height:7px;border-radius:99px;background:rgba(255,255,255,.08);overflow:hidden}
.strength .bar>span{display:block;height:100%}
.strength .num{font-size:12px;color:var(--muted)}
.iconbtn{padding:5px 9px;font-size:12px}
button:disabled{opacity:.55;cursor:not-allowed}
button:disabled:hover{border-color:var(--line);color:var(--text)}
.section{margin-top:28px}
.section h2{font-size:18px;margin:0 0 12px;display:flex;align-items:center;gap:10px}
.section h2 span{font-size:12px;color:var(--muted);font-weight:400}
.findings{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:8px 18px}
.finding{display:flex;gap:12px;padding:12px 0;border-bottom:1px dashed rgba(34,48,77,.7);align-items:flex-start}
.finding:last-child{border-bottom:none}
.finding .txt{flex:1}
.finding .t{font-weight:600;font-size:14px}
.finding .d{color:var(--muted);font-size:12.5px;margin-top:2px}
.finding .s{color:var(--muted);font-size:12px;white-space:nowrap}
.empty{color:var(--muted);padding:26px;text-align:center}
footer{color:var(--muted);font-size:12px;margin-top:28px;text-align:center;line-height:1.9}
footer strong{color:#cbd5e1}
@media (max-width:640px){.page{padding:18px 12px 40px}h1{font-size:22px}.hero{padding:20px}}
"""

_HTML_BODY = """
<div class="page">
  <header class="hero">
    <div class="brandrow">
      <div class="brand">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <path d="M2 8.5a15 15 0 0 1 20 0"/><path d="M5 12a10.5 10.5 0 0 1 14 0"/>
          <path d="M8.5 15.5a6 6 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1.6" fill="currentColor" stroke="none"/>
        </svg>
        WiFiKey · 本地 WiFi 安全审计
      </div>
      <div class="ts">生成时间 __GENERATED__ · 平台 __PLATFORM__</div>
    </div>
    <h1>WiFi 密码与安全审计报告</h1>
    <p class="sub">共 <strong>__TOTAL__</strong> 个已保存网络，其中 __WITH_PWD__ 个可读取密码。全部数据仅来自本机配置，未进行任何网络探测。</p>
    <div class="stats">__STATS__</div>
  </header>

  <div class="toolbar">
    <input id="search" type="search" placeholder="搜索 SSID / 安全类型 / 密码片段">
    <select id="filter">
      <option value="all">全部网络</option>
      <option value="has_pwd">仅含密码</option>
      <option value="weak">弱密码（&lt;55 分）</option>
      <option value="open">开放网络</option>
      <option value="legacy">WEP / TKIP / WPA</option>
      <option value="hidden">隐藏 SSID</option>
    </select>
    <button id="toggle" class="primary">隐藏密码</button>
    <button id="copyall">复制全部（SSID:密码）</button>
    <span class="hint" id="count"></span>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th data-sort="ssid">SSID</th>
          <th data-sort="security">安全类型</th>
          <th data-sort="cipher">加密</th>
          <th data-sort="password">密码</th>
          <th data-sort="score">强度</th>
          <th data-sort="risk">风险</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>

  <section class="section">
    <h2>风险汇总 <span>共 __FINDINGS_COUNT__ 项（按严重程度排序）</span></h2>
    <div class="findings" id="findings"></div>
  </section>

  <footer>
    <strong>安全提示</strong>：本报告包含明文 WiFi 密码，等同于本机“已保存网络”的钥匙。<br>
    请仅保存在可信位置，不要上传网盘、聊天工具或公开仓库；分享前建议使用「隐藏密码」导出。<br>
    由 WiFiKey v__VERSION__ 生成 · 仅读取本机已保存配置，不具备破解未保存网络的能力。
  </footer>
</div>
"""

_HTML_SCRIPT = """
<script id="payload" type="application/json">__DATA__</script>
<script>
(function(){
  var payload = JSON.parse(document.getElementById('payload').textContent);
  var rows = payload.rows || [];
  var reveal = payload.reveal;
  var sevLabel = {critical:'严重', high:'高危', medium:'中危', low:'低危', info:'提示'};
  var sevClass = {critical:'crit', high:'high', medium:'med', low:'low', info:'info'};
  var sortKey = 'ssid', sortDir = 1;
  var filtered = rows.slice();

  function esc(v){
    return String(v == null ? '' : v).replace(/[&<>"']/g, function(ch){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
    });
  }

  function strengthColor(score){
    if(score < 35) return 'var(--crit)';
    if(score < 55) return 'var(--high)';
    if(score < 80) return 'var(--med)';
    return 'var(--ok)';
  }

  function render(){
    var query = document.getElementById('search').value.trim().toLowerCase();
    var filter = document.getElementById('filter').value;
    filtered = rows.filter(function(r){
      if(filter === 'has_pwd' && !r.has_password) return false;
      if(filter === 'weak' && !(r.has_password && r.score < 55)) return false;
      if(filter === 'open' && !/open/i.test(r.security)) return false;
      if(filter === 'legacy' && !/wep|tkip|^wpa/i.test(r.security + ' ' + r.cipher)) return false;
      if(filter === 'hidden' && !r.hidden) return false;
      if(!query) return true;
      var hay = (r.ssid + ' ' + r.security + ' ' + (r.password || '') + ' ' + (r.issues || []).join(' ')).toLowerCase();
      return hay.indexOf(query) !== -1;
    });
    filtered.sort(function(a, b){
      var x = a[sortKey], y = b[sortKey];
      if(typeof x === 'number' && typeof y === 'number') return (x - y) * sortDir;
      if(sortKey === 'risk'){
        var order = {critical:0, high:1, medium:2, low:3, info:4, '':9};
        return ((order[x] === undefined ? 9 : order[x]) - (order[y] === undefined ? 9 : order[y])) * sortDir;
      }
      return String(x).localeCompare(String(y), 'zh-Hans-CN') * sortDir;
    });

    document.getElementById('count').textContent = '显示 ' + filtered.length + ' / ' + rows.length + ' 个网络';
    var tbody = document.getElementById('rows');
    if(!filtered.length){
      tbody.innerHTML = '<tr><td colspan="7" class="empty">没有匹配的网络</td></tr>';
      return;
    }
    tbody.innerHTML = filtered.map(function(r, i){
      var pwd = r.has_password ? (reveal ? r.password : '••••••••') : '—';
      var pwdClass = r.has_password && reveal ? 'pwd' : 'pwd masked';
      var risk = r.risk ? '<span class="badge ' + (sevClass[r.risk] || 'info') + '">' + sevLabel[r.risk] + '</span>' : '<span class="badge ok">未发现风险</span>';
      var scoreCell = r.has_password
        ? '<div class="strength"><div class="bar"><span style="width:' + r.score + '%;background:' + strengthColor(r.score) + '"></span></div><span class="num">' + r.grade + ' · ' + r.score + '</span></div>'
        : '<span class="hint">无密码</span>';
      var lock = r.hidden ? '<span class="lock">隐藏</span>' : '';
      var issues = (r.issues && r.issues.length) ? r.issues.join('；') : '';
      var pwdBtn = payload.canReveal
        ? '<button class="iconbtn" data-copy="pwd" data-i="' + i + '">复制密码</button> '
        : '<button class="iconbtn" disabled>密码已隐藏</button> ';
      return '<tr>' +
        '<td class="ssid">' + esc(r.ssid) + lock + '</td>' +
        '<td><span class="badge ' + (r.security === 'Open' ? 'crit' : 'info') + '">' + esc(r.security) + '</span></td>' +
        '<td>' + esc(r.cipher) + '</td>' +
        '<td class="' + pwdClass + '" title="' + esc(issues) + '">' + esc(pwd) + '</td>' +
        '<td>' + scoreCell + '</td>' +
        '<td>' + risk + '</td>' +
        '<td>' + pwdBtn +
        '<button class="iconbtn" data-copy="ssid" data-i="' + i + '">复制 SSID</button></td>' +
      '</tr>';
    }).join('');

    Array.prototype.forEach.call(tbody.querySelectorAll('button[data-copy]'), function(btn){
      btn.onclick = function(){
        var row = filtered[Number(btn.getAttribute('data-i'))];
        var text = btn.getAttribute('data-copy') === 'pwd' ? (row.password || '') : row.ssid;
        if(!text){ btn.textContent = '无密码'; return; }
        copyText(text, btn);
      };
    });
  }

  function copyText(text, btn){
    var done = function(){
      if(!btn) return;
      var old = btn.textContent;
      btn.textContent = '已复制';
      setTimeout(function(){ btn.textContent = old; }, 1400);
    };
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(done, function(){ fallback(text, done); });
    } else { fallback(text, done); }
  }

  function fallback(text, done){
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch(e) {}
    document.body.removeChild(ta);
  }

  var findings = payload.findings || [];
  var fBox = document.getElementById('findings');
  if(findings.length){
    fBox.innerHTML = findings.map(function(f){
      return '<div class="finding"><span class="badge ' + (sevClass[f.severity] || 'info') + '">' + sevLabel[f.severity] + '</span>' +
        '<div class="txt"><div class="t">' + esc(f.title) + '</div><div class="d">' + esc(f.detail) + '</div></div>' +
        '<span class="s">' + esc(f.ssid) + '</span></div>';
    }).join('');
  } else {
    fBox.innerHTML = '<div class="empty">未发现明显风险</div>';
  }

  document.getElementById('search').addEventListener('input', render);
  document.getElementById('filter').addEventListener('change', render);
  document.getElementById('toggle').addEventListener('click', function(){
    if(!payload.canReveal) return;
    reveal = !reveal;
    this.textContent = reveal ? '隐藏密码' : '显示密码';
    render();
  });
  if(!payload.canReveal){
    var t = document.getElementById('toggle');
    t.disabled = true; t.textContent = '报告已隐藏密码';
    var ca = document.getElementById('copyall');
    ca.disabled = true; ca.textContent = '密码已隐藏';
  }
  document.getElementById('copyall').addEventListener('click', function(){
    var text = filtered.filter(function(r){ return r.has_password; }).map(function(r){
      return r.ssid + ':' + (reveal ? r.password : '');
    }).filter(function(s){ return s.indexOf(':') > -1 && s.split(':').slice(1).join(''); }).join('\\n');
    copyText(text, this);
  });
  document.querySelectorAll('thead th[data-sort]').forEach(function(th){
    th.addEventListener('click', function(){
      var key = th.getAttribute('data-sort');
      if(sortKey === key){ sortDir *= -1; } else { sortKey = key; sortDir = 1; }
      render();
    });
  });
  render();
})();
</script>
"""


def to_html(networks: list[WifiNetwork], reveal: bool = True, platform: str | None = None) -> str:
    report = audit_networks(networks)
    rows = build_rows(networks, reveal)
    meta = _meta(platform)
    stats = report.stats

    stat_cards = []
    cards = [
        ("已保存网络", str(stats["total"]), "个"),
        ("可读取密码", str(stats["with_password"]), "个"),
        ("弱密码", str(stats["weak"]), "个"),
        ("开放 / WEP", str(stats["open"] + stats["wep"]), "个"),
        ("整体健康度", str(report.score), "/ 100"),
    ]
    for label, value, unit in cards:
        bar = (
            f'<div class="scorebar"><span style="width:{report.score}%"></span></div>'
            if label == "整体健康度"
            else ""
        )
        stat_cards.append(
            f'<div class="stat"><div class="k">{label}</div>'
            f'<div class="v">{value}<small>{unit}</small></div>{bar}</div>'
        )

    findings = [
        {"ssid": f.ssid, "severity": f.severity, "title": f.title, "detail": f.detail}
        for f in report.findings
    ]
    payload = {
        "tool": meta["tool"],
        "version": meta["version"],
        "generated_at": meta["generated_at"],
        "platform": meta["platform"],
        "reveal": bool(reveal),
        "canReveal": bool(reveal),
        "score": report.score,
        "rows": rows,
        "findings": findings,
    }
    data_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")

    html = (
        "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>WiFi 密码与安全审计报告</title>\n<style>"
        + _HTML_STYLE
        + "</style>\n</head>\n<body>"
        + _HTML_BODY
        + _HTML_SCRIPT
        + "\n</body>\n</html>\n"
    )
    replacements = {
        "__GENERATED__": meta["generated_at"],
        "__PLATFORM__": meta["platform"],
        "__TOTAL__": str(stats["total"]),
        "__WITH_PWD__": str(stats["with_password"]),
        "__STATS__": "".join(stat_cards),
        "__FINDINGS_COUNT__": str(len(findings)),
        "__VERSION__": meta["version"],
        "__DATA__": data_json,
    }
    for key, value in replacements.items():
        html = html.replace(key, value)
    return html


def save_text_file(content: str, path: str | Path, encoding: str = "utf-8") -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding=encoding)
    return target
