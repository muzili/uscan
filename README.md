# UniversalScanner (Rust)

多品牌网络摄像机 / 门禁 / UPS 设备发现工具的 **C# UniversalScanner 行为级复刻**（原项目为
C#/.NET 4.5 WinForms，约 8300 行）。本仓库为库 crate（`universal-scanner`）+ CLI（`uscan`），
**不做 UI**。

- **27 个协议引擎** = 26 个 C# 引擎复刻 + 新增 **ARP/GARP** L2 发现引擎（原项目没有）；
  其中 SSDP / WSDiscovery / Hikvision 为组播类，Axis / Google / Arecont 为 mDNS broker 消费者，
  其余为广播类。
- **mDNS broker**：单一 DNS-wire 解析 + 域名注册表，供 3 个 mDNS 消费者共享（端口 5353）。
- 许可：**LGPL-3.0**（与原项目一致）。
- 对应设计文档：`../UniversalScanner/docs/superpowers/specs/2026-08-20-universal-scanner-rust-design.md`

> 本 README 主体为中文，关键章节附英文小节；英文摘要见文末 [English summary](#english-summary)。

## 1. 构建 / Build

```bash
cargo build --release
```

**系统依赖：** Linux 需 **libpcap**（`libpcap-dev` + `pkg-config`）；macOS 自带 libpcap。
ARP 设备的 serial 会追加 MAC 厂家标注（`84:7b:57:xx:xx:xx (Intel Corporate)`）。
OUI 数据源优先级：系统 `ieee-data` 包 → `uscan update-oui` 下载的缓存
（`~/.cache/uscan/oui.txt`，IEEE 官方源）→ **内置压缩数据库**（`oui_data/compact.txt.gz`，
约 400KB、39,982 条，开箱即用）。重新生成内置库：

```bash
python3 - <<'PY'
import gzip, re, urllib.request
req = urllib.request.Request("https://standards-oui.ieee.org/oui/oui.txt",
                             headers={"User-Agent": "Mozilla/5.0"})
out = [f"{m.group(1)}\t{m.group(2)}"
       for m in map(lambda l: re.match(r'^([0-9A-F]{6})\s+\(base 16\)\s*(.+?)\s*$', l.decode()),
                    urllib.request.urlopen(req))]
open("universal-scanner/src/oui_data/compact.txt.gz", "wb").write(gzip.compress("\n".join(out).encode(), 9))
PY
```
Rust ≥ 1.75（edition 2021，MSRV 1.75）。

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev pkg-config
```

## 2. 用法 / CLI usage

省略子命令 = 默认 `scan`：

```bash
# 默认扫描（流式子网探测）
uscan

# 指定协议 + 输出格式
uscan scan --protocols ssdp,hikvision --format csv
uscan scan --protocols dahua --format json --show-version
uscan scan --format tsv --rescan 30 --timeout 120   # 每 30s 重扫，120s 后退出

# 配置：TOML 文件（--config）覆盖内置默认；CLI flag 覆盖文件
uscan scan --config ./universal-scanner.toml

# 离线回归：重放 .selftest fixture（默认全部；可加协议名过滤）
uscan selftest
uscan selftest google

# 把 fixture 包装成单个 UDP loopback pcap 包（用于抓包回放）
uscan selftest2pcap in.selftest out.pcap
uscan selftest2pcap in.selftest out.pcap --dest-port 1900

# 列出全部协议引擎 + mDNS broker 行
uscan list-protocols
```

**输出格式**（`--format`）：`table`（默认）/ `csv` / `json`（JSON Lines）/ `tsv`。
批量输出加 `--batch`（结束时按发现顺序一次性输出）。
CSV/TSV 表头恒为 `protocol,version,ip,type,serial`（version 列对齐 C# 隐藏列导出；
每字段按 C# `exportAsCSV` 规则双引号包裹、内部 `"` 翻倍）。

**配置文件（TOML，10 个开关，CLI > 文件 > 内置默认）：**

```toml
enable_ipv4              = true   # 启用 IPv4 发现
enable_ipv6              = false  # 启用 IPv6 发现
force_link_local         = true   # 保留 link-local (fe80::) 设备
force_zeroconf           = false  # 保留 zeroconf (169.254/16) 设备
force_generic_protocols  = false  # 按 protocol+IP 去重（否则仅按 IP）
debug_mode               = false  # 调试日志（含探测字节）
port_sharing             = true   # SO_REUSEADDR 端口共享
onvif_verbatim           = false  # ONVIF 原样上报
dahua_net_scan           = false  # Dahua 子网扫描（netscan）
arp_enabled              = true   # ARP/GARP L2 发现（Rust 新增）
```

查找顺序：`--config` > `$UNIVERSAL_SCANNER_CONFIG` > `$XDG_CONFIG_HOME/universal-scanner/config.toml` >
`~/.config/universal-scanner/config.toml`；不存在则静默跳过。未知键报错（含键名）。

## 3. 权限 / Permissions

- **ARP 捕获** 需要 Linux `CAP_NET_RAW`（或 root）/ macOS `/dev/bpf` 读权限。
- 权限不足时 **ARP 引擎优雅降级**：日志 `warn: ARP discovery disabled (no capture permission)`，
  **其余引擎不受影响**，扫描照常进行。
- 全局 socket 端口被占且 `port_sharing` 关闭时，该 socket 降级为 `warn` + 跳过（C# 行为一致），
  不导致整次扫描失败。

## 4. 测试 Fixtures

`universal-scanner/tests/fixtures/` 下 **31 个 `.selftest` 报文**（覆盖全部 27 个引擎，部分引擎
双 fixture），多数来自 C# 仓库真实报文；`Arp.selftest` 为**合成** fixture（42 字节 GARP 帧，
无 C# 对应物，spec §3.6）。每个引擎的源地址合成规则为 `240.0.<id>.<minor>`（id = 注册表 ID）。

`uscan selftest` 即离线回归（无需真实硬件），全部 fixture 全绿即代表解析层行为级一致。
说明见 `universal-scanner/tests/fixtures/README.md`。

## 5. 库用法 / Library usage

```rust
use universal_scanner::{Config, Scanner, DeviceTable};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (mut scanner, mut rx) = Scanner::new(Config::default(), None, None)?; // 全部引擎
    scanner.start().await?;   // 绑定接口 socket + spawn 接收任务
    scanner.scan()?;          // 发送一轮探测（立即返回）
    let mut table = DeviceTable::new(Config::default().force_generic_protocols);
    while let Some(d) = rx.recv().await {            // 逐条消费发现结果
        if let Some(d) = table.add(d, true, false) { println!("{:?}", d); }
    }
    scanner.stop().await?;    // 取消全部任务
    Ok(())
}
```

API：`Scanner::new(Config, Option<&[protocol]>, Option<pcap_out>) -> (Scanner, rx)` →
`start().await` → `scan()` → drain `rx`（`Device`）→ `DeviceTable::add` 去重 + 版本择优 → `stop().await`。
`Scanner` 可重复 `start()`（每次按注册表重建全新引擎实例 + 新 `CancellationToken`）。

## 6. 范围外 / Out of scope

- WinForms UI（表格交互、CSV 对话框、双击开浏览器、单实例、更新检查）。
- Windows 平台与 Windows 注册表（配置改为 TOML + CLI）。
- C# 中已禁用的 Dlink / Hid / Microsens 协议。
- Device Management / Streaming 层子系统：ONVIF SOAP 配置、DHCP vendor option、HTTP/REST、
  RTSP、SIP/GB28181、云注册 —— 各自独立，后续按 **ONVIF Profile T** 优先拆子项目（spec §10）。

## 7. Quality（T58）

质量门禁：`cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`。

- **universal-scanner lib 行覆盖率：93.38%**（13,151 行，871 未覆盖；`cargo llvm-cov --workspace` 实测）。
- 全工作区测试：**239 passed / 0 failed**。
- 未追覆盖率（已文档化排除）：`arp/capture.rs`（pcap 捕获线程，需 root + libpcap）、
  `netscan.rs`（需活动网卡 + 254 主机扫描）、`engine.rs` 的 `send_all`（需真实 socket 发送）。
  这些路径不计入 80% 目标。

## English summary

UniversalScanner (Rust) is a behavioral re-implementation of the C# UniversalScanner network
device-discovery tool, split into a library crate (`universal-scanner`) and a CLI (`uscan`), with
no UI. It ships **27 protocol engines** (26 faithful C# ports + a new ARP/GARP L2 engine) plus a
shared mDNS broker, licensed LGPL-3.0.

Build with `cargo build --release` (needs `libpcap-dev` + `pkg-config` on Linux; Rust ≥ 1.75).
CLI: `uscan` (default scan), `uscan scan --protocols ... --format ...`, `uscan selftest`,
`uscan selftest2pcap in.selftest out.pcap`, `uscan list-protocols`. Configuration merges
CLI > TOML file > defaults across 10 boolean keys. ARP capture needs `CAP_NET_RAW` (Linux) or
`/dev/bpf` (macOS); without it the ARP engine degrades gracefully while all other engines run.
Offline regression uses 31 `.selftest` fixtures (the synthetic `Arp.selftest` included) replayed by
`uscan selftest`. Library entry points: `Scanner::new` → `start().await` → `scan()` → drain the
`Device` receiver → `DeviceTable::add` → `stop().await`. Measured lib line coverage: 93.38%
(239 tests passing).
