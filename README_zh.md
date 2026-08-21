# UniversalScanner（Rust 版）

C# [UniversalScanner](https://github.com/julienblitte/UniversalScanner) 的 Rust 移植——多品牌
网络摄像机 / 门禁 / UPS 设备发现工具。原项目是约 8300 行的 C#/.NET 4.5 WinForms 程序；这里
重新实现为库 crate（`universal-scanner`）+ CLI（`uscan`），不做 UI。

[English README](README.md)

## 它做什么

`uscan` 通过组播 / 广播 / 网卡定向 socket 发送 UDP 探测报文，把应答的设备逐条打印出来：
协议、版本、IP、MAC、型号、序列号。每个厂商协议一个引擎，共 28 个：

- 26 个是 C# 引擎的 1:1 复刻（探测字节、端口、解析、fallback 行为一致）；
- 2 个为本仓库新增：**ARP/GARP**（libpcap L2 捕获）与 **TVT**（MHED 组播协议，逆向自实机抓包）；
- **mDNS broker**（5353）统一解析 DNS-wire 应答，供 Axis / Google Cast / Arecont 三个
  mDNS 引擎消费，而不是各自维护监听 socket。

行为级对齐 C# 原版是验收标准，且离线可验证：32 个 `.selftest` 报文 fixture 走与实扫完全
相同的解析路径，`uscan selftest` 全绿即代表解析层行为未漂移。

## 环境要求

- Rust ≥ 1.75（edition 2021）
- Linux：`libpcap-dev` + `pkg-config`（`pcap` crate 链接系统 libpcap）；macOS 自带 libpcap

## 构建

```bash
cargo build --release
```

产物：`target/release/uscan`。

## 用法

省略子命令即默认扫描：

```bash
uscan
```

输出示例（默认格式为 `table`，这里用 CSV 展示）：

```
$ uscan scan --timeout 5 --format csv
protocol,version,ip,mac,type,serial
"SSDP","0","192.168.1.111","","Private Upnp SDK","device_3_0-0067120380000304"
"Hikvision","1","192.168.1.101","","DS-2CD3T25-I3","DS-2CD3T25-I320200730AACHE40182"
"Dahua","1","192.168.1.111","BC:32:5F:71:9B:03","IP Camera","0067120380000304"
```

更多示例：

```bash
uscan scan --protocols ssdp,hikvision --format csv
uscan scan --protocols dahua --format json --show-version
uscan scan --format tsv --rescan 30 --timeout 120   # 每 30s 重扫，120s 后退出
```

### 命令

| 命令 | 作用 |
|---|---|
| `uscan [scan]` | 扫描（默认命令） |
| `uscan selftest [engine]` | 离线重放 fixture（全部，或按引擎名过滤，不区分大小写） |
| `uscan selftest2pcap IN OUT [--dest-port N]` | 把 fixture 包装成单个 UDP loopback pcap 包；OUT 已存在时报错退出 |
| `uscan list-protocols` | 引擎表：ID、名称、端口、监听方式 |
| `uscan update-oui` | 下载 IEEE OUI 厂家数据库到 `~/.cache/uscan/oui.txt` |
| `uscan tvt-set --mac M --ip I [flags]` | 给 TVT 摄像机设置静态 IP（L2 set-IP 组播，MHED type 3） |

`tvt-set` 按 100ms 间隔连发 3 次。常用 flag：`--dhcp`（设备切回 DHCP，ip/mask/gateway
不生效）、`--dry-run`（打印报文 hex，密码区清零，不发送）、`--password`（管理员密码，
≤21 字节，包内 base64）、`--interface`（指定出接口 IP）。协议逆向自实机抓包（参考
`tvt-iptool-linux`）；改完可用 `uscan scan --protocols TVT` 验证——同一 serial 应以新 IP
再现。

### scan 常用 flag

| Flag | 含义 |
|---|---|
| `--protocols a,b,c` | 引擎过滤（不区分大小写，缺省全部） |
| `--format table\|csv\|json\|tsv` | 输出格式；`json` 为 JSON Lines |
| `--batch` | 结束时按发现顺序一次性输出 |
| `--rescan SECS` / `--timeout SECS` | 重扫间隔 / 超时后优雅退出 |
| `--show-version` | 显示 Version 列 |
| `--pcap-out PATH` | 把探测/应答写入 pcap |
| `--config PATH` | TOML 配置文件（见下） |
| `--arp` / `--no-arp` | ARP/GARP 引擎开关（默认关闭） |
| `--no-color` | 禁用着色 |

下面的 10 个配置开关同时有 CLI flag（`--enable-ipv6`、`--no-debug`、`--dahua-net-scan`
等）；CLI 优先。

### 输出

设备发现即流式打印；`--batch` 缓冲到扫描结束（超时或 Ctrl-C）再按发现顺序输出。

CSV/TSV 表头恒为 `protocol,version,ip,mac,type,serial`。引号规则对齐 C# `exportAsCSV`
（每字段双引号包裹、内部 `"` 翻倍），与原工具导出的文件可比对。`mac` 列为 Rust 版新增，
位于 ip 之后；协议应答不含 MAC 的引擎（SSDP / WSDiscovery / Hikvision 等）该列为空。

### 配置

优先级：CLI flag > TOML 文件 > 内置默认。

查找顺序：`--config PATH` > `$UNIVERSAL_SCANNER_CONFIG` >
`$XDG_CONFIG_HOME/universal-scanner/config.toml` > `~/.config/universal-scanner/config.toml`；
文件不存在静默跳过，未知键报错（含键名）。

```toml
enable_ipv4              = true   # 启用 IPv4 发现
enable_ipv6              = false  # 启用 IPv6 发现
force_link_local         = true   # 保留 link-local (fe80::) 设备
force_zeroconf           = false  # 保留 zeroconf (169.254/16) 设备
force_generic_protocols  = false  # 按 protocol+IP 去重（关闭时仅按 IP）
debug_mode               = false  # 调试日志（含探测字节）
port_sharing             = true   # SO_REUSEADDR 端口共享
onvif_verbatim           = false  # WSDiscovery 使用 ONVIF 原始 payload
dahua_net_scan           = false  # Dahua 子网扫描（Dahua2 netscan）
arp_enabled              = false  # ARP/GARP L2 引擎（Rust 新增）
```

### 权限与降级

- ARP 引擎捕获原始帧：Linux 需 `CAP_NET_RAW`（或 root），macOS 需 `/dev/bpf` 读权限。
  权限不足时打印 `warn: ARP discovery disabled (no capture permission)`，其余引擎不受
  影响——这也是 `arp_enabled` 默认关闭的原因之一。
- 端口被占且 `port_sharing` 关闭时，该 socket 降级为 warn 并跳过（与 C# 行为一致）；
  单个端口冲突不会导致整次扫描失败。

### OUI 厂家标注

ARP 引擎报告的 MAC 会追加厂家标注，如 `84:7b:57:xx:xx:xx (Intel Corporate)`。查找顺序：
系统 `ieee-data` 包 → `~/.cache/uscan/oui.txt`（`uscan update-oui` 下载）→ 内置压缩数据库
（约 407KB、39,982 条 IEEE 数据），零配置可用。重新生成内置库：
`universal-scanner/src/oui_data/README.md`。

## 协议引擎

`uscan list-protocols` 打印同一张表。注册表 ID 沿用 C# 原版（也决定 selftest 源地址
`240.0.<id>.<minor>`）；ID 21/22/27 是 C# 已禁用的 Dlink / Hid / Microsens 空位，未实现。

| ID | 引擎 | 端口 | 监听 | |
|---:|---|---|---|---|
| 1 | SSDP | 1900 | multicast 239.255.255.250:1900 | UPnP rootdevice |
| 2 | WSDiscovery | 3702 | multicast 239.255.255.250:3702 | WS-Discovery / ONVIF 探测 |
| 3 | Dahua | 5050 | global + ifaces :5050 | 旧版探测 |
| 4 | Dahua | 37810 | multicast 239.255.255.251:37810 | 子网扫描（netscan） |
| 5 | Hikvision | 37020 | multicast 239.255.255.250:37020 | |
| 6 | Axis | 5353 | mDNS broker | |
| 7 | Bosch | 1758 | global + ifaces :1758 | 视频服务器 |
| 8 | Google | 5353 | mDNS broker | Chromecast |
| 9 | Hanwha | 7711 | global + ifaces :7711 | 三星 |
| 10 | Vivotek | 10000 | ifaces only :10000 | |
| 11 | Sony | 2380 | ifaces only :2380 | |
| 12 | Ubiquiti | 10001 | global + ifaces :10001 | UniFi |
| 13 | 360Vision | 3600 | global + ifaces :3600 | |
| 14 | NiceVision | 2007 | global + ifaces :2007 | |
| 15 | Panasonic | 10670 | global + ifaces :10670 | |
| 16 | Arecont | 5353 | mDNS broker | |
| 17 | GigEVision | 3956 | ifaces only :3956 | |
| 18 | VStarcam | 8600 | global + ifaces :8600 | |
| 19 | Eaton | 4679 | global + ifaces :4679 | IPM / UPS |
| 20 | Foscam | 10000 | global + ifaces :10000 | |
| 23 | Lantronix | 30718 | global + ifaces :30718 | 亦覆盖 Vauban |
| 24 | Microchip | 30303 | global + ifaces :30303 | 亦覆盖 GCE Electronics |
| 25 | Advantech | 5048 | ifaces only :5048 | |
| 26 | Eden | 8088 | global + ifaces :8088 | Eden Optima |
| 28 | CyberPower | 53566 | global + ifaces :53566 | UPS |
| 29 | MSSQL | 1434 | global + ifaces :1434 | SQL Server Browser |
| 30 | ARP | — | pcap L2 捕获 | ARP/GARP，Rust 新增 |
| 31 | TVT | 23456 | multicast 234.55.55.55/.56:23456 | MHED，逆向自实机 |

mDNS broker 本身无注册表 ID。

## 库用法

```rust
use universal_scanner::{Config, Scanner, DeviceTable};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (mut scanner, mut rx) = Scanner::new(Config::default(), None, None)?; // 全部引擎
    scanner.start().await?;    // 绑定 socket，spawn 接收任务
    scanner.scan()?;           // 发送一轮探测（立即返回）
    let mut table = DeviceTable::new(Config::default().force_generic_protocols);
    while let Some(d) = rx.recv().await {
        if let Some(d) = table.add(d, true, false) {  // 去重 + 版本择优
            println!("{:?}", d);
        }
    }
    scanner.stop().await?;
    Ok(())
}
```

`Scanner::new(config, protocols, pcap_out)` 按注册表构建引擎集（名称过滤不区分大小写，
拼错会列出可选值）。生命周期可重复：每次 `start()` 重建全新引擎实例与取消令牌；
`stop()` 取消并 join 全部任务。

## 测试

- `cargo test --workspace` —— 268 个测试全部通过（撰写时）。
- `uscan selftest` —— 离线回归。`universal-scanner/tests/fixtures/` 下 32 个 fixture：
  30 个来自 C# 仓库真实报文；`Arp.selftest` 为合成（42 字节 GARP 帧，无 C# 对应物）；
  `TVT.selftest` 来自实机抓包（已脱敏）。
- 覆盖率（`cargo llvm-cov --workspace`）：库 crate 行覆盖 92.57%（14,663 行、1,089 行未覆盖）。
  未覆盖部分是有意排除的：`arp/capture.rs`（pcap 捕获线程，需 root + 活动网卡）、
  `netscan.rs`（真实 254 主机扫描）、`engine.rs`（真实 socket 发送）。

## 目录结构

```
universal-scanner/     # 库 crate
  src/scanner.rs       # 运行时：引擎注册表、start/scan/stop
  src/engine.rs        # ScanEngine trait、EngineContext
  src/devices.rs       # Device、DeviceTable（去重、版本择优）
  src/net.rs           # socket 封装：global / interface / multicast
  src/mdns.rs          # mDNS broker（DNS wire 解析 + 域名注册表）
  src/arp/             # ARP 帧构建/解析、pcap 捕获/注入
  src/protocols/       # 28 个引擎，每协议一个文件
  src/oui.rs           # IEEE OUI 查询
  src/selftest.rs      # fixture 重放表
  src/tvt_provision.rs # TVT L2 set-IP 报文
  tests/fixtures/      # 32 个 .selftest 报文
uscan/                 # CLI crate
  src/cli.rs           # clap 命令定义
  src/run.rs           # 扫描循环：流式 / 重扫 / 超时 / 信号
  src/output.rs        # table / csv / json / tsv 渲染
  src/config.rs        # CLI > TOML > 默认 三层合并
```

## 范围外

- WinForms UI：表格交互、CSV 对话框、双击开浏览器、单实例检查、更新检查。
- Windows 平台。C# 的注册表配置改为 TOML + CLI flag。
- C# 已禁用的 Dlink / Hid / Microsens 协议。
- C# 项目中的设备管理 / 流媒体层（ONVIF SOAP 配置、DHCP vendor option、HTTP/REST、RTSP、
  SIP/GB28181、云注册）——后续独立拆项目，ONVIF Profile T 优先。

## 来源

- 原工具：Julien Blitte 的 [UniversalScanner (C#)](https://github.com/julienblitte/UniversalScanner)，
  LGPL-3.0。其协议均通过抓包观察逆向（未反编译），目的是系统互操作。
- 本移植的设计文档：
  `../UniversalScanner/docs/superpowers/specs/2026-08-20-universal-scanner-rust-design.md`
  （位于 C# 仓库树内）。

## 许可

LGPL-3.0（与原项目一致），见 [LICENSE](LICENSE)。
