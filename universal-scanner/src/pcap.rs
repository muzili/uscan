//! pcap：极简 IPv4-only writer（magic 0xa1b2c3d4，C# PCapFile 对齐）。

use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::SystemTime;

/// 极简 pcap writer（对应 C# PCapFile）：仅 IPv4（C# 对 IPv6 会写损坏头，Rust 跳过，spec §8.2）。
pub struct PcapWriter {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    count: u64,
}

impl PcapWriter {
    pub fn new(path: &std::path::Path) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, // magic 0xa1b2c3d4（native 字节序）
            0x02, 0x00, 0x04, 0x00, // version 2.4
            0, 0, 0, 0, // timezone
            0, 0, 0, 0, // sigfigs
            0xdc, 0x05, 0, 0, // snaplen 1500
            1, 0, 0, 0, // linktype 1 (EN10MB)
        ])?;
        Ok(Self {
            inner: Mutex::new(Inner { file, count: 0 }),
        })
    }

    /// 追加一个 UDP 包；IPv6 端点返回 None（跳过）。成功返回累计包数。
    pub fn append_udp(
        &self,
        ts: SystemTime,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
    ) -> Option<u64> {
        let (src4, dst4) = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => return None,
        };
        let mut inner = self.inner.lock().unwrap();
        let age = ts
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let udp_len = 8u16 + payload.len() as u16;
        let ip_len = 20u16 + udp_len;
        let frame_len = (14u16 + ip_len) as u32;

        let mut rec = Vec::with_capacity(16 + frame_len as usize);
        rec.extend_from_slice(&(age.as_secs() as u32).to_le_bytes());
        rec.extend_from_slice(&age.subsec_micros().to_le_bytes());
        rec.extend_from_slice(&frame_len.to_le_bytes());
        rec.extend_from_slice(&frame_len.to_le_bytes());
        // Ethernet II（C# MAC 规则：02:00:00 + 端点 IP 末 3 字节）
        rec.extend_from_slice(&[
            0x02,
            0x00,
            0x00,
            dst4.octets()[1],
            dst4.octets()[2],
            dst4.octets()[3],
        ]);
        rec.extend_from_slice(&[
            0x02,
            0x00,
            0x00,
            src4.octets()[1],
            src4.octets()[2],
            src4.octets()[3],
        ]);
        rec.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4
        rec.push(0x45);
        rec.push(0);
        rec.extend_from_slice(&ip_len.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.push(254); // TTL（C#）
        rec.push(17); // UDP
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&src4.octets());
        rec.extend_from_slice(&dst4.octets());
        // UDP
        rec.extend_from_slice(&src.port().to_be_bytes());
        rec.extend_from_slice(&dst.port().to_be_bytes());
        rec.extend_from_slice(&udp_len.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(payload);

        if inner.file.write_all(&rec).is_err() {
            return None;
        }
        inner.count += 1;
        Some(inner.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn global_header_layout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let w = PcapWriter::new(&path).unwrap();
        drop(w);
        let b = std::fs::read(&path).unwrap();
        assert_eq!(b.len(), 24);
        assert_eq!(&b[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]); // magic 0xa1b2c3d4 native
        assert_eq!(&b[4..6], &[0x02, 0x00]); // major 2
        assert_eq!(&b[6..8], &[0x04, 0x00]); // minor 4
        assert_eq!(&b[16..20], &[0xdc, 0x05, 0, 0]); // snaplen 1500
        assert_eq!(&b[20..24], &[1, 0, 0, 0]); // linktype EN10MB
    }

    #[test]
    fn record_layout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let w = PcapWriter::new(&path).unwrap();
        let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let n = w
            .append_udp(
                ts,
                "127.0.0.1:1024".parse().unwrap(),
                "192.168.1.9:1900".parse().unwrap(),
                b"hello",
            )
            .unwrap();
        assert_eq!(n, 1);
        drop(w);
        let b = std::fs::read(&path).unwrap();
        let frame = 14u32 + 20 + 8 + 5; // eth + ip + udp + payload
        assert_eq!(b.len(), 24 + 16 + frame as usize);
        // record header
        assert_eq!(&b[24..28], &1_700_000_000u32.to_le_bytes());
        assert_eq!(&b[28..32], &0u32.to_le_bytes()); // usec
        assert_eq!(&b[32..36], &frame.to_le_bytes());
        // ethernet: MAC = 02:00:00 + IP 末 3 字节（C# PCapFile）
        assert_eq!(&b[40..46], &[0x02, 0, 0, 168, 1, 9]); // dst 192.168.1.9
        assert_eq!(&b[46..52], &[0x02, 0, 0, 0, 0, 1]); // src 127.0.0.1
        assert_eq!(&b[52..54], &[0x08, 0x00]); // IPv4
                                               // IPv4 头
        assert_eq!(b[54], 0x45);
        assert_eq!(&b[56..58], &33u16.to_be_bytes()); // total length 20+13
        assert_eq!(b[62], 254); // TTL
        assert_eq!(b[63], 17); // UDP
        assert_eq!(&b[66..70], &[127, 0, 0, 1]);
        assert_eq!(&b[70..74], &[192, 168, 1, 9]);
        // UDP
        assert_eq!(&b[74..76], &1024u16.to_be_bytes());
        assert_eq!(&b[76..78], &1900u16.to_be_bytes());
        assert_eq!(&b[78..80], &13u16.to_be_bytes());
        assert_eq!(&b[82..87], b"hello");
    }

    #[test]
    fn ipv6_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let w = PcapWriter::new(&path).unwrap();
        let r = w.append_udp(
            SystemTime::now(),
            "[::1]:1".parse().unwrap(),
            "[::1]:2".parse().unwrap(),
            b"x",
        );
        assert!(r.is_none());
    }
}
