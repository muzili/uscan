//! ARP/GARP L2 扫描引擎。
pub mod capture;
pub mod frame;

#[cfg(test)]
mod tests {
    use crate::arp::frame;

    #[test]
    fn request_roundtrip() {
        let f = frame::build_request(
            [0xAA; 6],
            "192.168.1.2".parse().unwrap(),
            "192.168.1.99".parse().unwrap(),
        );
        assert_eq!(f.len(), 42);
        let p = frame::parse(&f).unwrap();
        assert_eq!(p.op, frame::ARP_OP_REQUEST);
        assert_eq!(p.src_mac, [0xAA; 6]);
        assert_eq!(p.sender_ip.to_string(), "192.168.1.2");
        assert_eq!(p.target_ip.to_string(), "192.168.1.99");
        assert_eq!(p.target_mac, [0u8; 6]); // who-has 目标 MAC 全零
    }

    #[test]
    fn garp_detection() {
        let f = frame::build_request(
            [0xBB; 6],
            "10.0.0.7".parse().unwrap(),
            "10.0.0.7".parse().unwrap(),
        );
        assert!(frame::is_garp(&frame::parse(&f).unwrap()));
    }

    #[test]
    fn reply_frame() {
        // op=2 构造：target = 询问者
        let f = frame::build_reply(
            [0xCC; 6],
            "10.0.0.8".parse().unwrap(),
            [0xDD; 6],
            "10.0.0.1".parse().unwrap(),
        );
        let p = frame::parse(&f).unwrap();
        assert_eq!(p.op, frame::ARP_OP_REPLY);
        assert!(!frame::is_garp(&p));
    }

    #[test]
    fn rejects_non_arp_ethertype() {
        let mut f = frame::build_request(
            [0xAA; 6],
            "1.2.3.4".parse().unwrap(),
            "1.2.3.5".parse().unwrap(),
        );
        f[12] = 0x08;
        f[13] = 0x00; // IPv4
        assert!(frame::parse(&f).is_none());
    }

    #[test]
    fn rejects_short_frame() {
        assert!(frame::parse(&[0u8; 41]).is_none());
    }

    #[tokio::test]
    async fn fixture_is_garp() {
        let data = tokio::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Arp.selftest"
        ))
        .await
        .unwrap();
        assert_eq!(data.len(), 42);
        let p = frame::parse(&data).unwrap();
        assert!(frame::is_garp(&p));
        assert_eq!(p.sender_ip.to_string(), "192.168.1.50");
        assert_eq!(p.src_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }
}
