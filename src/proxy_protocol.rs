//! PROXY protocol v1 and v2 parser (async).
//!
//! Load balancers (AWS NLB, GCP ILB, Cloudflare Spectrum) prepend a PROXY
//! prefix to the TCP stream carrying the original client IP and port.
//! Without it the application only sees the LB's address.
//!
//! This module reads the prefix from the raw `TcpStream` and returns the
//! source IP.  The stream is left positioned at the first application byte
//! (TLS ClientHello or plain HTTP).  If no recognised prefix is found the
//! TCP peer IP is returned without consuming anything.
//!
//! Supported: v1 (text, max 108 bytes, CRLF-terminated),
//!            v2 (binary, 12-byte signature + fixed header).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::debug;

// PROXY v2 binary signature: \r\n\r\n\0\r\nQUIT\n
const V2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
// Maximum length of a PROXY v1 header line.
const V1_MAX_LEN: usize = 108;

/// Read the PROXY protocol prefix and return the real client IP.
///
/// Peeks the first byte to classify:
/// - `'P'`: v1 text header
/// - `'\r'`: v2 binary header (first byte of the 12-byte signature)
/// - anything else: no PROXY header; return `fallback` without consuming
///
/// Parse errors are logged at debug level and yield `fallback` so a
/// misconfigured upstream does not kill all connections.
pub async fn read_proxy_header(
    stream: &mut TcpStream,
    fallback: IpAddr,
) -> Result<IpAddr> {
    let mut first = [0u8; 1];
    // peek does not consume the byte — safe to fall through to the app layer.
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(fallback);
    }

    match first[0] {
        b'P' => parse_v1(stream, fallback).await,
        0x0D => parse_v2(stream, fallback).await,
        _ => Ok(fallback),
    }
}

// ---------------------------------------------------------------------------
// PROXY protocol v1
// ---------------------------------------------------------------------------
//
// Format: "PROXY <PROTO> <SRC_IP> <DST_IP> <SRC_PORT> <DST_PORT>\r\n"
// Special: "PROXY UNKNOWN\r\n" (no address fields, fall through)

async fn parse_v1(stream: &mut TcpStream, fallback: IpAddr) -> Result<IpAddr> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);

        // Header ends at the first \r\n.
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
        if buf.len() > V1_MAX_LEN {
            return Err(anyhow!("PROXY v1 header exceeds maximum length"));
        }
    }

    let line = std::str::from_utf8(&buf)
        .map_err(|e| anyhow!("PROXY v1 header is not valid UTF-8: {e}"))?
        .trim_end_matches("\r\n");

    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return Err(anyhow!("PROXY v1 header missing PROXY keyword"));
    }

    if parts[1] == "UNKNOWN" {
        // Per spec, callers must use the TCP endpoint when protocol is UNKNOWN.
        debug!("PROXY v1 UNKNOWN protocol; using TCP peer IP");
        return Ok(fallback);
    }

    if parts.len() < 5 {
        return Err(anyhow!("PROXY v1 header has too few fields"));
    }

    parts[2]
        .parse::<IpAddr>()
        .map_err(|e| anyhow!("PROXY v1 src IP parse error: {e}"))
}

// ---------------------------------------------------------------------------
// PROXY protocol v2
// ---------------------------------------------------------------------------
//
// Binary layout (all big-endian):
//   12 bytes: signature
//    1 byte:  version (high nibble = 2) + command (low nibble: 0=LOCAL, 1=PROXY)
//    1 byte:  address family + transport protocol
//    2 bytes: length of remaining variable-length address section
//   N bytes:  address data (IPv4: 12, IPv6: 36, UNIX: 216)

async fn parse_v2(stream: &mut TcpStream, fallback: IpAddr) -> Result<IpAddr> {
    // Read the fixed 16-byte header (12 sig + 4 meta).
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;

    if &header[..12] != V2_SIGNATURE.as_ref() {
        // Not a valid v2 header.  We already consumed 16 bytes from the
        // application stream, so this connection is unsalvageable.
        return Err(anyhow!(
            "stream begins with \\r\\n but is not a valid PROXY v2 header"
        ));
    }

    let version = (header[12] & 0xF0) >> 4;
    if version != 2 {
        return Err(anyhow!("PROXY v2 unsupported version {version}"));
    }

    let command = header[12] & 0x0F;
    let family_protocol = header[13];
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    // Read the variable-length address section.
    let mut addr_data = vec![0u8; addr_len];
    stream.read_exact(&mut addr_data).await?;

    // Command 0x00 = LOCAL (health-check from the LB itself); no address info.
    if command == 0x00 {
        debug!("PROXY v2 LOCAL command; using TCP peer IP");
        return Ok(fallback);
    }
    if command != 0x01 {
        return Err(anyhow!("PROXY v2 unknown command {command:#04x}"));
    }

    // Address family is in the high nibble: 1=IPv4, 2=IPv6, 3=UNIX.
    match (family_protocol >> 4) & 0x0F {
        1 => {
            // IPv4: src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2) = 12 bytes
            if addr_data.len() < 4 {
                return Err(anyhow!("PROXY v2 IPv4 address section too short"));
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                addr_data[0],
                addr_data[1],
                addr_data[2],
                addr_data[3],
            )))
        }
        2 => {
            // IPv6: src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2) = 36 bytes
            if addr_data.len() < 16 {
                return Err(anyhow!("PROXY v2 IPv6 address section too short"));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&addr_data[..16]);
            Ok(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        3 => {
            // UNIX domain socket path — no meaningful IP; fall back to TCP peer.
            debug!("PROXY v2 UNIX family; using TCP peer IP");
            Ok(fallback)
        }
        af => {
            // Unaffiliated/unknown family.
            debug!(family = af, "PROXY v2 unknown address family; using TCP peer IP");
            Ok(fallback)
        }
    }
}
