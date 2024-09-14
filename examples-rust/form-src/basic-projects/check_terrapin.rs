extern crate serde;
extern crate serde_json;

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use serde::{Serialize, Serializer};
use serde_json::json;

#[derive(Clone, Copy)]
enum ScanMode {
    ServerScan,
    ClientScan,
}

const CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";
const ETM_SUFFIX: &str = "-etm@openssh.com";
const CBC_SUFFIX: &str = "-cbc";
const KEX_STRICT_INDICATOR_CLIENT: &str = "kex-strict-c-v00@openssh.com";
const KEX_STRICT_INDICATOR_SERVER: &str = "kex-strict-s-v00@openssh.com";

#[derive(Debug, Serialize)]
struct Report {
    remote_addr: String,
    is_server: bool,
    banner: String,
    supports_chacha20: bool,
    supports_cbc_etm: bool,
    supports_strict_kex: bool,
    #[serde(serialize_with = "serialize_is_vulnerable")]
    vulnerable: bool,
}

fn serialize_is_vulnerable<S>(report: &Report, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(report.is_vulnerable())
}

impl Report {
    fn is_vulnerable(&self) -> bool {
        (self.supports_chacha20 || self.supports_cbc_etm) && !self.supports_strict_kex
    }
}

fn scan(address: &str, scan_mode: ScanMode, verbose: bool) -> io::Result<Report> {
    scan_with_timeout(address, scan_mode, verbose, None)
}

fn scan_with_timeout(
    address: &str,
    scan_mode: ScanMode,
    verbose: bool,
    timeout: Option<Duration>,
) -> io::Result<Report> {
    let conn = match scan_mode {
        ScanMode::ServerScan => TcpStream::connect(address)?,
        ScanMode::ClientScan => {
            let listener = TcpListener::bind(address)?;
            if verbose {
                eprintln!("Listening for incoming client connection on {}", address);
            }
            let (conn, _) = listener.accept()?;
            conn
        }
    };

    let mut conn = BufReader::new(conn);
    let remote_banner = exchange_banners(&mut conn)?;
    let remote_kex_init = receive_remote_kex_init(&mut conn)?;

    let supports_chacha20 = remote_kex_init
        .encryption_algorithms_client_to_server
        .contains(&CHACHA20_POLY1305.to_string())
        || remote_kex_init
            .encryption_algorithms_server_to_client
            .contains(&CHACHA20_POLY1305.to_string());
    let supports_cbc_etm = (remote_kex_init
        .encryption_algorithms_client_to_server
        .iter()
        .any(|alg| alg.ends_with(CBC_SUFFIX))
        && remote_kex_init
            .mac_algorithms_client_to_server
            .iter()
            .any(|alg| alg.ends_with(ETM_SUFFIX)))
        || (remote_kex_init
            .encryption_algorithms_server_to_client
            .iter()
            .any(|alg| alg.ends_with(CBC_SUFFIX))
            && remote_kex_init
                .mac_algorithms_server_to_client
                .iter()
                .any(|alg| alg.ends_with(ETM_SUFFIX)));
    let supports_strict_kex = remote_kex_init
        .kex_algorithms
        .contains(&KEX_STRICT_INDICATOR_SERVER.to_string())
        || (scan_mode == ScanMode::ClientScan
            && remote_kex_init
                .kex_algorithms
                .contains(&KEX_STRICT_INDICATOR_CLIENT.to_string()));

    Ok(Report {
        remote_addr: address.to_string(),
        is_server: scan_mode == ScanMode::ServerScan,
        banner: remote_banner,
        supports_chacha20,
        supports_cbc_etm,
        supports_strict_kex,
        vulnerable: false, // This field will be computed dynamically during serialization
    })
}

#[derive(Debug)]
struct BinaryPacket {
    packet_length: u32,
    padding_length: u8,
    payload: Vec<u8>,
    padding: Vec<u8>,
    mac: Vec<u8>,
}

#[derive(Debug)]
struct SshMsgKexInit {
    msg_type: u8,
    cookie: Vec<u8>,
    kex_algorithms: Vec<String>,
    server_host_key_algorithms: Vec<String>,
    encryption_algorithms_client_to_server: Vec<String>,
    encryption_algorithms_server_to_client: Vec<String>,
    mac_algorithms_client_to_server: Vec<String>,
    mac_algorithms_server_to_client: Vec<String>,
    compression_algorithms_client_to_server: Vec<String>,
    compression_algorithms_server_to_client: Vec<String>,
    languages_client_to_server: Vec<String>,
    languages_server_to_client: Vec<String>,
    first_kex_packet_follows: bool,
    flags: u32,
}

fn read_single_packet(conn: &mut BufReader<TcpStream>) -> io::Result<BinaryPacket> {
    let mut pkt_length_bytes = [0u8; 4];
    conn.read_exact(&mut pkt_length_bytes)?;
    let packet_length = u32::from_be_bytes(pkt_length_bytes);

    if packet_length > 35000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet length is larger than 35000 bytes",
        ));
    }

    let mut pkt_bytes = vec![0u8; packet_length as usize];
    conn.read_exact(&mut pkt_bytes)?;

    let padding_length = pkt_bytes[0];
    let payload = pkt_bytes[1..(packet_length as usize - padding_length as usize)].to_vec();
    let padding = pkt_bytes[(packet_length as usize - padding_length as usize)..].to_vec();

    Ok(BinaryPacket {
        packet_length,
        padding_length,
        payload,
        padding,
        mac: Vec::new(),
    })
}

fn exchange_banners(conn: &mut BufReader<TcpStream>) -> io::Result<String> {
    conn.get_mut()
        .write_all(b"SSH-2.0-TerrapinVulnerabilityScanner\r\n")?;
    conn.get_mut().flush()?;

    loop {
        let mut line = String::new();
        conn.read_line(&mut line)?;
        if line.starts_with("SSH-1.99") || line.starts_with("SSH-2.0") {
            return Ok(line.trim().to_string());
        }
    }
}

fn parse_name_list(pkt: &BinaryPacket, offset: usize) -> io::Result<(Vec<String>, usize)> {
    if pkt.payload.len() < offset + 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "not enough bytes to read name list length",
        ));
    }
    let length = u32::from_be_bytes([
        pkt.payload[offset],
        pkt.payload[offset + 1],
        pkt.payload[offset + 2],
        pkt.payload[offset + 3],
    ]) as usize;

    if pkt.payload.len() < offset + 4 + length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "not enough bytes to read name list",
        ));
    }

    let name_list_bytes = &pkt.payload[offset + 4..offset + 4 + length];
    let name_list = String::from_utf8(name_list_bytes.to_vec())
        .unwrap()
        .split(',')
        .map(String::from)
        .collect();

    Ok((name_list, 4 + length))
}

fn parse_kex_init(pkt: &BinaryPacket) -> io::Result<SshMsgKexInit> {
    let mut offset = 0;

    let msg_type = pkt.payload[offset];
    offset += 1;
    let cookie = pkt.payload[offset..offset + 16].to_vec();
    offset += 16;

    let mut parse_name_list_at = |offset: usize| parse_name_list(pkt, offset);

    let (kex_algorithms, len) = parse_name_list_at(offset)?;
    offset += len;
    let (server_host_key_algorithms, len) = parse_name_list_at(offset)?;
    offset += len;
    let (encryption_algorithms_client_to_server, len) = parse_name_list_at(offset)?;
    offset += len;
    let (encryption_algorithms_server_to_client, len) = parse_name_list_at(offset)?;
    offset += len;
    let (mac_algorithms_client_to_server, len) = parse_name_list_at(offset)?;
    offset += len;
    let (mac_algorithms_server_to_client, len) = parse_name_list_at(offset)?;
    offset += len;
    let (compression_algorithms_client_to_server, len) = parse_name_list_at(offset)?;
    offset += len;
    let (compression_algorithms_server_to_client, len) = parse_name_list_at(offset)?;
    offset += len;
    let (languages_client_to_server, len) = parse_name_list_at(offset)?;
    offset += len;
    let (languages_server_to_client, len) = parse_name_list_at(offset)?;
    offset += len;

    let first_kex_packet_follows = pkt.payload[offset] != 0;
    offset += 1;

    let flags = u32::from_be_bytes([
        pkt.payload[offset],
        pkt.payload[offset + 1],
        pkt.payload[offset + 2],
        pkt.payload[offset + 3],
    ]);

    Ok(SshMsgKexInit {
        msg_type,
        cookie,
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
        languages_client_to_server,
        languages_server_to_client,
        first_kex_packet_follows,
        flags,
    })
}

fn receive_remote_kex_init(conn: &mut BufReader<TcpStream>) -> io::Result<SshMsgKexInit> {
    loop {
        let pkt = read_single_packet(conn)?;
        if pkt.payload[0] == 20 {
            return parse_kex_init(&pkt);
        }
    }
}

fn main() {
    // Example usage:
    let address = "127.0.0.1:22";
    let scan_mode = ScanMode::ServerScan;
    let verbose = true;
    let report = scan(address, scan_mode, verbose).expect("Failed to scan");

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}