//! 非 scan 命令：selftest / selftest2pcap / list-protocols（T55）。

use crate::cli::OutputFormat;
use crate::output;
use std::net::SocketAddr;
use std::path::Path;
use universal_scanner::pcap::PcapWriter;
use universal_scanner::selftest;

/// 重放 .selftest fixture（默认全部；`protocol` 不区分大小写过滤）。
/// exit 0 = 全部重放完成；任一 fixture 缺失/重放 Err → stderr + exit 1。
pub fn run_selftest(protocol: Option<&str>) -> i32 {
    let want = protocol.map(|s| s.to_ascii_lowercase());
    let replays = selftest::replays();
    let selected: Vec<&selftest::Replay> = replays
        .iter()
        .filter(|re| {
            want.as_ref()
                .map(|w| re.engine_name.to_ascii_lowercase() == *w)
                .unwrap_or(true)
        })
        .collect();
    if let Some(w) = &want {
        if selected.is_empty() {
            eprintln!("error: unknown protocol: {w}");
            return 1;
        }
    }
    let mut failed = false;
    for re in &selected {
        match selftest::replay(re) {
            Ok(devs) => {
                println!("== {} [{}] (src {})", re.engine_name, re.fixture, re.source);
                for d in &devs {
                    println!(
                        "   {}",
                        output::render_row(d, OutputFormat::Table, true, false)
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "error: replay failed for {} [{}]: {e}",
                    re.engine_name, re.fixture
                );
                failed = true;
            }
        }
    }
    if failed {
        1
    } else {
        0
    }
}

/// 把 fixture 包装成单个 UDP loopback pcap 包。
/// 输出文件已存在 → 硬错误 exit 1（spec §8.2，C# 为追加，Rust 改为硬错误）。
/// 时间戳 = 输入文件 mtime（UTC）。
pub fn run_selftest2pcap(in_file: &Path, out_file: &Path, dest_port: u16) -> i32 {
    if out_file.exists() {
        eprintln!("error: output file already exists: {}", out_file.display());
        return 1;
    }
    let payload = match std::fs::read(in_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: read fixture {}: {e}", in_file.display());
            return 1;
        }
    };
    let ts = match std::fs::metadata(in_file).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: read mtime {}: {e}", in_file.display());
            return 1;
        }
    };
    let writer = match PcapWriter::new(out_file) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: create pcap {}: {e}", out_file.display());
            return 1;
        }
    };
    let src: SocketAddr = "127.0.0.1:1024".parse().expect("valid src");
    let dst: SocketAddr = format!("127.0.0.1:{dest_port}").parse().expect("valid dst");
    match writer.append_udp(ts, src, dst, &payload) {
        Some(n) => {
            println!("wrote {n} packet(s) to {}", out_file.display());
            0
        }
        None => {
            eprintln!("error: failed to append packet to {}", out_file.display());
            1
        }
    }
}

/// 列出全部协议引擎（registry）+ 末尾一行 mDNS broker 说明。
pub fn run_list_protocols() -> i32 {
    let registry = universal_scanner::protocols::registry();
    println!(
        "{:<3} | {:<12} | {:<7} | {:<32} | Description",
        "ID", "Name", "Port", "Listen"
    );
    for (id, e) in &registry {
        let m = proto_meta(*id);
        println!(
            "{:<3} | {:<12} | {:<7} | {:<32} | {}",
            id,
            e.name(),
            m.port,
            m.listen,
            m.desc
        );
    }
    println!();
    println!(
        "mDNS broker 5353 (shared, no registry ID): Axis / Google / Arecont consume mDNS via the broker."
    );
    0
}

/// 监听方式与描述（按 registry ID 区分；Dahua/Dahua2/Lantronix 同名靠 ID 区分）。
struct Meta {
    port: &'static str,
    listen: &'static str,
    desc: &'static str,
}

fn proto_meta(id: u16) -> Meta {
    match id {
        1 => Meta {
            port: "1900",
            listen: "multicast 239.255.255.250:1900",
            desc: "UPnP SSDP rootdevice discovery",
        },
        2 => Meta {
            port: "3702",
            listen: "multicast 239.255.255.250:3702",
            desc: "WS-Discovery device probe",
        },
        3 => Meta {
            port: "5050",
            listen: "global+ifaces :5050",
            desc: "Dahua (legacy) probe",
        },
        4 => Meta {
            port: "37810",
            listen: "multicast 239.255.255.251:37810",
            desc: "Dahua subnet scan (netscan)",
        },
        5 => Meta {
            port: "37020",
            listen: "multicast 239.255.255.250:37020",
            desc: "Hikvision device discovery",
        },
        6 => Meta {
            port: "5353",
            listen: "mdns broker 5353",
            desc: "Axis (mDNS consumer)",
        },
        7 => Meta {
            port: "1758",
            listen: "global+ifaces :1758",
            desc: "Bosch video server discovery",
        },
        8 => Meta {
            port: "5353",
            listen: "mdns broker 5353",
            desc: "Google Cast (mDNS consumer)",
        },
        9 => Meta {
            port: "7711",
            listen: "global+ifaces :7711",
            desc: "Hanwha camera discovery",
        },
        10 => Meta {
            port: "10000",
            listen: "ifaces only :10000",
            desc: "Vivotek camera discovery",
        },
        11 => Meta {
            port: "2380",
            listen: "ifaces only :2380",
            desc: "Sony camera discovery",
        },
        12 => Meta {
            port: "10001",
            listen: "global+ifaces :10001",
            desc: "Ubiquiti UniFi discovery",
        },
        13 => Meta {
            port: "3600",
            listen: "global+ifaces :3600",
            desc: "360 Vision camera discovery",
        },
        14 => Meta {
            port: "2007",
            listen: "global+ifaces :2007",
            desc: "NiceVision discovery",
        },
        15 => Meta {
            port: "10670",
            listen: "global+ifaces :10670",
            desc: "Panasonic camera discovery",
        },
        16 => Meta {
            port: "5353",
            listen: "mdns broker 5353",
            desc: "Arecont (mDNS consumer)",
        },
        17 => Meta {
            port: "3956",
            listen: "ifaces only :3956",
            desc: "GigE Vision discovery",
        },
        18 => Meta {
            port: "8600",
            listen: "global+ifaces :8600",
            desc: "VStarcam camera discovery",
        },
        19 => Meta {
            port: "4679",
            listen: "global+ifaces :4679",
            desc: "Eaton IPM discovery",
        },
        20 => Meta {
            port: "10000",
            listen: "global+ifaces :10000",
            desc: "Foscam camera discovery",
        },
        23 => Meta {
            port: "30718",
            listen: "global+ifaces :30718",
            desc: "Lantronix/Vauban discovery",
        },
        24 => Meta {
            port: "30303",
            listen: "global+ifaces :30303",
            desc: "Microchip discovery",
        },
        25 => Meta {
            port: "5048",
            listen: "ifaces only :5048",
            desc: "Advantech camera discovery",
        },
        26 => Meta {
            port: "8088",
            listen: "global+ifaces :8088",
            desc: "Eden Optima discovery",
        },
        28 => Meta {
            port: "53566",
            listen: "global+ifaces :53566",
            desc: "CyberPower UPS discovery",
        },
        29 => Meta {
            port: "1434",
            listen: "global+ifaces :1434",
            desc: "MSSQL browser discovery",
        },
        30 => Meta {
            port: "—",
            listen: "pcap ARP (L2)",
            desc: "ARP/GARP host discovery (L2 capture)",
        },
        31 => Meta {
            port: "23456",
            listen: "multicast 234.55.55.55/.56 :23456",
            desc: "TVT camera discovery (MHED, reverse-engineered)",
        },
        _ => Meta {
            port: "—",
            listen: "—",
            desc: "",
        },
    }
}

/// 下载 IEEE OUI 厂家数据库到用户缓存（ARP 厂家标注数据源）。
pub fn run_update_oui() -> i32 {
    match universal_scanner::oui::download() {
        Ok(dest) => {
            println!("OUI database saved to {}", dest.display());
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// TVT L2 set-IP（MHED type 3）：构造 + 组播发送（3 次 @100ms）。
/// exit 0 = 已发送（或 --dry-run 打印完成）；1 = 参数/构造/发送错误（消息到 stderr）。
pub fn run_tvt_set(args: &crate::cli::TvtSetArgs) -> i32 {
    use universal_scanner::tvt_provision::{self, SetIpRequest};

    let mac = match tvt_provision::parse_mac(&args.mac) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let req = SetIpRequest {
        mac,
        password: args.password.clone(),
        new_ip: args.ip,
        subnet_mask: args.mask,
        gateway: args.gateway,
        dhcp: args.dhcp,
        protocol_version: args.version,
    };
    let packet = match tvt_provision::build_set_ip_request(&req) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if args.dry_run {
        print!("{}", tvt_provision::hex_dump(&packet));
        return 0;
    }
    match tvt_provision::send_set_ip(&req, args.interface) {
        Ok(()) => {
            println!(
                "sent {}B TVT set-IP packet to {}:{} (mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, dhcp={})",
                tvt_provision::PACKET_SIZE,
                tvt_provision::SET_IP_GROUP,
                tvt_provision::SET_IP_PORT,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                req.dhcp
            );
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
