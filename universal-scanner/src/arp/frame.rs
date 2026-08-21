//! ARP/GARP 帧的构造与解析（纯函数）。
use std::net::Ipv4Addr;

pub const ETH_ARP: u16 = 0x0806;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;
pub const FRAME_LEN: usize = 14 + 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpFrame {
    pub op: u16,
    pub src_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

fn build(
    op: u16,
    src_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[6..12].copy_from_slice(&src_mac); // src MAC（dst MAC 由调用方语义决定，默认全零/broadcast 在外层填）
    f[12] = 0x08;
    f[13] = 0x06;
    // ARP payload @14
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // htype Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&op.to_be_bytes());
    f[22..28].copy_from_slice(&src_mac);
    f[28..32].copy_from_slice(&sender_ip.octets());
    f[32..38].copy_from_slice(&target_mac);
    f[38..42].copy_from_slice(&target_ip.octets());
    f
}

pub fn build_request(src_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; 42] {
    let mut f = build(ARP_OP_REQUEST, src_mac, sender_ip, [0u8; 6], target_ip);
    f[..6].copy_from_slice(&[0xFF; 6]); // broadcast dst
    f
}

pub fn build_reply(
    src_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    build(ARP_OP_REPLY, src_mac, sender_ip, target_mac, target_ip)
}

pub fn parse(frame: &[u8]) -> Option<ArpFrame> {
    if frame.len() < FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETH_ARP {
        return None;
    }
    let p = &frame[14..];
    Some(ArpFrame {
        op: u16::from_be_bytes([p[6], p[7]]),
        src_mac: [p[8], p[9], p[10], p[11], p[12], p[13]],
        sender_ip: Ipv4Addr::new(p[14], p[15], p[16], p[17]),
        target_mac: [p[18], p[19], p[20], p[21], p[22], p[23]],
        target_ip: Ipv4Addr::new(p[24], p[25], p[26], p[27]),
    })
}

/// GARP：who-has 且 sender IP == target IP（设备自宣告）
pub fn is_garp(f: &ArpFrame) -> bool {
    f.op == ARP_OP_REQUEST && f.sender_ip == f.target_ip
}
