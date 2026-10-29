[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/) [![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

# WiFiKey · WiFi 密码管理与无线环境安全审计

跨平台工具：读取**本机已经保存过**的 WiFi 配置，展示密码、评估强度、审计风险，并导出一份可搜索、可排序的 HTML 报告；同时可以只读扫描周围可见的无线网络，评估无线环境。

> 能力边界：
> - 密码只来自设备上已保存的配置文件（你曾经连接过并保存密码的网络）。
> - `scan` 只列出网卡可见的网络广播信息（SSID / BSSID / 信号 / 信道 / 加密类型），与系统 WiFi 列表一致。
> - 不做抓包、不做暴力破解、不创建热点、不尝试连接任何未保存的网络，**也无法获取未保存网络的密码**。

## 相比同类开源项目的增强点

| 能力 | 常见 WiFi 密码查看器 | WiFiKey |
| --- | --- | --- |
| Windows 解析方式 | 依赖 `netsh` 文本输出，遇到非英文系统或特殊字符易失败 | 优先导出并解析 WLANProfile **XML**，标签与系统语言无关；文本解析作为兜底，中英文标签均支持 |
| Linux / macOS | 多数只支持 Windows | NetworkManager keyfile、wpa_supplicant、macOS Keychain / 机场 plist 三套后端 |
| 密码分析 | 只显示密码 | 密码强度评分（0-100）、弱口令/连续字符/纯数字识别、**跨网络复用密码检测** |
| 安全审计 | 无 | WEP / TKIP / WPA1 / 开放网络 / 隐藏 SSID 风险分级，输出严重-高危-中危-低危汇总 |
| 报告导出 | TXT / CSV | JSON、CSV、TXT、**自包含交互式 HTML**（搜索、筛选、排序、一键复制、密码遮罩） |
| 图形界面 | 多数只有 CLI 或仅单一平台 | 内置 Tkinter 桌面界面，跨平台可用 |
| 二维码分享 | 无或依赖在线服务 | 标准 `WIFI:` 二维码，本地生成（终端 ASCII / PNG / SVG） |
| 隐私保护 | 无 | `--mask` 隐藏密码、`--no-passwords` 完全不读取密码，报告默认支持遮罩导出 |
| 周围网络扫描 | 无，或引导用户使用第三方探测工具 | `scan` 只读扫描可见网络：信号、信道、频段、加密类型、已保存标记，并做信道拥挤 / 开放网络 / 同名仿冒热点评估 |
| 依赖 | 常需第三方库 | 核心功能**零第三方依赖**，仅二维码功能可选安装 `qrcode` |

## 功能一览

- 列出全部已保存网络：SSID、安全类型、加密方式、密码、强度、风险、当前连接标记
- 扫描周围可见网络：信号强度、信道、频段（2.4G/5G/6G）、安全类型、同名 AP 数量、是否本机已保存
- 无线环境评估：开放 / WEP / 老式加密 / WPA3 占比，2.4GHz 信道拥挤度与空闲信道建议，**同名仿冒开放热点（evil twin）预警**
- 单网络详情：密码、强度构成、连接模式、隐藏状态、数据来源、关联风险
- 搜索与筛选：按名称/安全类型/密码片段搜索；只看有密码、弱密码、开放网络、老式加密、隐藏 SSID、当前连接
- 安全审计：整体健康度评分、风险分级、复用密码分组
- 导出：JSON / CSV / TXT / HTML；CSV 使用 UTF-8 BOM，Excel 可直接打开
- 二维码：终端 ASCII 渲染，或保存 PNG / SVG
- 桌面 GUI：表格浏览、显示/隐藏密码、复制、二维码、审计窗口、周围网络扫描窗口、导出报告
- 环境自检：`doctor` 检查平台后端、权限与可选依赖

## 安装与运行

要求 Python 3.10+（Windows / Linux / macOS）。核心功能无需安装任何第三方包。

```bash
# 方式一：直接运行（推荐，无需安装）
python -m wifikey

# 方式二：安装为命令
pip install -e .
wifikey
```

可选：安装二维码依赖

```bash
pip install qrcode           # 终端 ASCII 二维码
pip install qrcode pillow    # 另外支持导出 PNG
```

Windows 用户也可以直接双击 `run_gui.bat` 打开图形界面。

## 命令行用法

```bash
# 列出全部网络（默认）
python -m wifikey list

# 只看能读到密码的网络，并隐藏密码
python -m wifikey list --has-password --mask

# 只看弱密码 / 开放网络 / 老式加密
python -m wifikey list --weak
python -m wifikey list --open
python -m wifikey list --legacy

# 搜索并排序（score 为密码强度从弱到强）
python -m wifikey list --search 5G --sort score

# 扫描周围可见的无线网络（只读，不连接、不破解）
python -m wifikey scan
python -m wifikey scan --band 5 --sort signal      # 只看 5GHz，按信号排序
python -m wifikey scan --open                      # 只看开放网络
python -m wifikey scan --saved                     # 只看本机保存过的网络
python -m wifikey scan --channel 6 --no-summary    # 只看 6 信道，不打印环境评估
python -m wifikey scan -f json -o scan.json        # 导出 JSON

# 查看单个网络详情，支持模糊匹配
python -m wifikey show "MyWiFi" --copy

# 生成二维码（终端 ASCII）
python -m wifikey qr "MyWiFi"
python -m wifikey qr "MyWiFi" -o wifi.png      # 需要 Pillow
python -m wifikey qr "MyWiFi" -o wifi.svg      # 仅需 qrcode

# 安全审计
python -m wifikey audit
python -m wifikey audit -f json -o audit.json

# 导出报告
python -m wifikey export -f html -o report.html      # 交互式 HTML 报告
python -m wifikey export -f csv  -o report.csv       # Excel 可直接打开
python -m wifikey export -f json -o report.json
python -m wifikey export -f txt  -o report.txt
python -m wifikey export -f html -o share.html --mask  # 分享前隐藏密码

# 图形界面
python -m wifikey gui

# 环境自检
python -m wifikey doctor
```

### 隐私模式

| 参数 | 行为 |
| --- | --- |
| `--mask` | 正常读取密码，但终端/报告中以 `••••••••` 显示 |
| `--no-passwords` | 完全不读取密码字段，只列出网络信息，适合演示或截图 |

`--mask` 与 `--no-passwords` 都可写在子命令前或后，例如 `wifikey --mask list` 或 `wifikey list --mask`。

## 图形界面

```bash
python -m wifikey gui
```

- 表格列：序号、SSID（★ 标记当前连接）、安全类型、加密、密码、强度、风险
- 默认隐藏密码，勾选“显示密码”后展示
- 双击或点击“复制密码”写入系统剪贴板
- “生成二维码”“安全审计”“导出 HTML / JSON / CSV”按钮
- “扫描周围网络”按钮：打开独立扫描窗口，列出周围可见网络并显示环境评估

## 各平台实现原理

### Windows

1. 优先执行 `netsh wlan export profile folder=<临时目录> key=clear`，解析导出的 `WLANProfile` XML。
   - XML 标签名（`SSID`、`authentication`、`encryption`、`keyMaterial`、`nonBroadcast` 等）与系统语言无关，中文/英文/日文系统结果一致。
   - 临时目录在读取后立即删除，不残留明文文件。
2. 对导出失败或被跳过的配置，回退到 `netsh wlan show profile name=... key=clear`，同时兼容英文与中文标签（`SSID name / SSID 名称`、`Cipher / 密码`、`Key Content / 关键内容`）。
3. 当前连接网络通过 `netsh wlan show interfaces` 获取。
4. 周围网络扫描：`netsh wlan show networks mode=bssid`，解析 `SSID / BSSID / Signal / Channel / Band / Authentication / Encryption`；兼容中文标签（`信号`、`信道`、`频道`、`波段`、`身份验证`、`加密`），同一 SSID 的多个 BSSID 按频段聚合，取信号最强的一条。

读取当前用户的配置通常不需要管理员权限；企业策略保护或受保护的密钥可能读不到密码。

### Linux

- NetworkManager：解析 `/etc/NetworkManager/system-connections/*.nmconnection`（`[wifi] ssid`、`[wifi-security] key-mgmt/psk`）。
- wpa_supplicant：解析 `/etc/wpa_supplicant/wpa_supplicant*.conf` 与用户目录配置中的 `network` 块。
- 无权限读取 keyfile 时，退回 `nmcli` 列出连接名称，并提示用 `sudo` 重新运行。
- 当前连接：`iwgetid -r`，或 `nmcli device status`。
- 周围网络扫描：`nmcli --terse --fields SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY device wifi list`，按 TSV 解析并还原 `\:` 转义；频率字段用于区分 2.4G / 5G / 6G。

### macOS

- `networksetup -listallhardwareports` 找到 Wi-Fi 设备，再 `-listpreferredwirelessnetworks` 列出首选网络。
- 通过 `security find-generic-password -D "AirPort network password" -a <SSID> -w` 读取钥匙串密码；首次读取可能弹出系统授权对话框。
- 若首选网络列表不可用，回退解析 `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`（经 `plutil` 转 JSON）获取 SSID 与安全类型。
- 部分企业级 802.1X 网络不会在本地保存共享密码，这是系统设计而非工具限制。
- 周围网络扫描：优先 `airport -s`（旧系统）；新版 macOS 已移除该工具，回退 `system_profiler SPAirPortDataType -json`，再回退文本解析。dBm 按 `2 × (dBm + 100)` 换算为 0-100 百分比。

## 安全审计规则

| 风险项 | 等级 | 说明 |
| --- | --- | --- |
| 开放网络 | 严重 | 无加密，任何人均可接入 |
| WEP 加密 | 严重 | 已被攻破，数分钟可破解 |
| TKIP 加密 | 高危 | 建议改为 CCMP / GCMP |
| 仅 WPA/WPA2 早期模式 | 高危 | 建议启用 WPA2-AES 或 WPA3 |
| 密码强度不足 | 高危 / 中危 | 评分低于 55（低于 35 为高危） |
| 密码跨网络复用 | 中危 | 一处泄露即影响多个网络 |
| 隐藏 SSID | 低危 | 隐藏 SSID 不提升安全性 |
| 企业级 802.1X | 提示 | 不保存共享密码，属正常现象 |

密码评分综合长度、字符集、信息熵，并对常见弱口令、纯数字、连续序列、重复字符等扣分，输出 0-100 分与 `极弱 / 弱 / 中 / 强` 等级。

### 周围无线环境评估（`scan`）

| 观察项 | 等级 | 说明 |
| --- | --- | --- |
| 同名仿冒开放热点 | 高危 | 附近的开放网络与你已保存的加密网络同名，可能是 evil twin，连接前请确认来源 |
| 2.4GHz 信道拥挤 | 低危 | 单个推荐信道（1/6/11）重叠网络 ≥ 8 个时提示，并给出相对空闲的信道建议 |
| 开放网络数量 | 提示 | 开放网络流量可被监听或劫持，避免在其上登录账号或支付 |
| WEP / TKIP / WPA1 数量 | 低危 | 他人网络的老式加密，仅作环境观察，不要连接 |
| WPA3 覆盖率 | 统计 | 可见网络中启用 WPA3 / SAE 的数量 |
| 本机已保存数量 | 统计 | 可见网络中，本机已保存过配置的数量（用 ★ 标记） |

`scan` 只是把网卡看到的广播信息整理出来，与系统 WiFi 列表一致，不涉及任何密码读取。

## HTML 报告

`wifikey export -f html` 生成**单文件、无外部依赖**的深色主题报告：

- 顶部统计卡片与健康度进度条
- 表格支持搜索、筛选（有密码 / 弱密码 / 开放 / 老式加密 / 隐藏 SSID）、点击表头排序
- 一键复制密码或 SSID、密码遮罩开关
- 底部按严重程度汇总所有风险项
- 使用 `--mask` 导出时，报告中的密码与 JSON 数据全部为遮罩值，适合分享

## 项目结构

```
wifikey/
├── __init__.py
├── __main__.py          # python -m wifikey
├── cli.py               # 命令行入口
├── gui.py               # Tkinter 图形界面
├── models.py            # 数据模型（WifiNetwork / ScanNetwork / Finding 等）
├── audit.py             # 密码强度与风险审计
├── scanner.py           # 周围网络只读扫描与环境评估
├── exporters.py         # JSON/CSV/TXT/HTML 与二维码
├── terminal.py          # 终端表格、详情、审计与扫描渲染
├── textutil.py          # 宽字符对齐、颜色与表格
├── clipboard.py         # 跨平台剪贴板
└── providers/
    ├── base.py
    ├── windows.py       # netsh XML + 文本兜底
    ├── linux.py         # NetworkManager + wpa_supplicant
    └── macos.py         # Keychain + networksetup + plist
tests/
├── test_wifikey.py      # 43 个单元测试
└── test_scan.py         # 21 个扫描解析 / 环境评估单元测试
```

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖各平台解析样例（含中文与英文 netsh 扫描输出、XML、keyfile、wpa_supplicant、nmcli、airport、system_profiler、macOS plist）、密码评分、审计规则、信道拥挤与仿冒热点判定、ANSI 清理、导出遮罩与二维码转义，不需要真实 WiFi 环境（共 64 个用例）。

## 常见问题

**为什么有的网络没有密码？**
开放网络本身没有密码；企业级 802.1X 网络不保存共享密码；个别密钥受系统保护或当前权限不足。

**Windows 需要管理员权限吗？**
读取当前用户保存的配置通常不需要。若返回空密码，可尝试以管理员身份运行；组策略下发的配置可能不可读。

**Linux 读不到密码？**
`/etc/NetworkManager/system-connections` 通常仅 root 可读，请使用 `sudo python -m wifikey list`。

**macOS 一直弹钥匙串授权？**
`security` 命令访问每个网络的密码时都可能触发一次系统授权，属于正常行为；也可在“钥匙串访问”中手动查看。

**会上传我的数据吗？**
不会。所有解析在本地完成，工具不包含任何网络请求；导出文件也只写到你指定的路径。

**`scan` 能读到别人的 WiFi 密码吗？**
不能，也不打算提供。周围网络的密码不存在于你的设备上；`scan` 只整理网卡可见的公开广播信息（SSID、信号、信道、加密类型），与手机/电脑系统里的 WiFi 列表完全一致。要“读取”未保存网络的密码只能靠抓包破解或攻击 WPS，这属于对他人网络的未授权访问。

**`scan` 扫描不到网络 / 只看到一个网络？**
Windows 需开启 WLAN AutoConfig 服务且无线网卡未被禁用；Linux 需要 `NetworkManager`；macOS 新版需允许 `system_profiler` 读取无线信息。部分系统会限制定期扫描，可稍等几秒后重试。

**扫描结果里的“已保存”是什么意思？**
表示该 SSID 在本机存在已保存的配置（你连过），此时才可能通过 `list` / `show` 查看它的密码。未保存的网络不会显示密码。

## 合规声明

本项目用于**找回自己设备上已保存的 WiFi 密码**、排查自身无线环境的安全配置。`scan` 仅做被动只读扫描，不连接、不破解、不获取任何未保存网络的密码。

请勿将本项目用于未授权访问他人网络或设备。未经授权破解他人 WiFi 属于违法行为（如中国《刑法》第 285 条、《网络安全法》），使用者需自行确保行为符合当地法律法规。

## License

MIT
