use anyhow::{anyhow, Result};
use nimble_util::hash::percent_encode;
use std::net::{Ipv4Addr, SocketAddrV4};
use windows_sys::core::w;
use windows_sys::Win32::Networking::WinHttp::*;

const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB cap for tracker responses
const MAX_PEERS_FROM_TRACKER: usize = 200; // Cap peers to prevent excessive memory/CPU usage

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerEvent {
    Started,
    Stopped,
    Completed,
    None,
}

impl TrackerEvent {
    fn as_str(&self) -> Option<&str> {
        match self {
            TrackerEvent::Started => Some("started"),
            TrackerEvent::Stopped => Some("stopped"),
            TrackerEvent::Completed => Some("completed"),
            TrackerEvent::None => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceRequest<'a> {
    pub info_hash: &'a [u8; 20],
    pub peer_id: &'a [u8; 20],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub compact: bool,
    pub event: TrackerEvent,
}

#[derive(Debug, Clone)]
pub struct AnnounceResponse {
    pub interval: u32,
    pub complete: Option<u32>,
    pub incomplete: Option<u32>,
    pub peers: Vec<SocketAddrV4>,
    pub failure_reason: Option<String>,
}

pub fn announce(base_url: &str, request: &AnnounceRequest) -> Result<AnnounceResponse> {
    let query = build_query_string(request)?;
    let url = if base_url.contains('?') {
        format!("{}&{}", base_url, query)
    } else {
        format!("{}?{}", base_url, query)
    };

    let response_data = http_get(&url)?;

    if response_data.len() > MAX_RESPONSE_SIZE {
        return Err(anyhow!(
            "tracker response too large: {} bytes",
            response_data.len()
        ));
    }

    parse_announce_response(&response_data)
}

fn build_query_string(req: &AnnounceRequest) -> Result<String> {
    let mut parts = Vec::new();

    let info_hash_encoded = percent_encode(req.info_hash);
    parts.push(format!("info_hash={}", info_hash_encoded));

    let peer_id_encoded = percent_encode(req.peer_id);
    parts.push(format!("peer_id={}", peer_id_encoded));

    parts.push(format!("port={}", req.port));
    parts.push(format!("uploaded={}", req.uploaded));
    parts.push(format!("downloaded={}", req.downloaded));
    parts.push(format!("left={}", req.left));

    if req.compact {
        parts.push("compact=1".to_string());
    }

    if let Some(event_str) = req.event.as_str() {
        parts.push(format!("event={}", event_str));
    }

    Ok(parts.join("&"))
}

fn http_get(url: &str) -> Result<Vec<u8>> {
    unsafe {
        let h_session = WinHttpOpen(
            w!("Nimble/1.0"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );

        if h_session.is_null() {
            return Err(anyhow!("WinHttpOpen failed"));
        }

        let result = http_get_inner(h_session, url);

        WinHttpCloseHandle(h_session);

        result
    }
}

unsafe fn http_get_inner(h_session: *mut std::ffi::c_void, url: &str) -> Result<Vec<u8>> {
    let parsed = parse_url(url)?;

    let host_wide = to_wide(&parsed.host);
    let h_connect = WinHttpConnect(h_session, host_wide.as_ptr(), parsed.port, 0);

    if h_connect.is_null() {
        return Err(anyhow!("WinHttpConnect failed"));
    }

    let path_wide = to_wide(&parsed.path);

    let flags = if parsed.is_https {
        WINHTTP_FLAG_SECURE
    } else {
        0
    };

    let h_request = WinHttpOpenRequest(
        h_connect,
        w!("GET"),
        path_wide.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null_mut(),
        flags,
    );

    if h_request.is_null() {
        WinHttpCloseHandle(h_connect);
        return Err(anyhow!("WinHttpOpenRequest failed"));
    }

    let send_result = WinHttpSendRequest(
        h_request,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        0,
        0,
    );

    if send_result == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        return Err(anyhow!("WinHttpSendRequest failed"));
    }

    let recv_result = WinHttpReceiveResponse(h_request, std::ptr::null_mut());

    if recv_result == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        return Err(anyhow!("WinHttpReceiveResponse failed"));
    }

    let mut status_code: u32 = 0;
    let mut status_code_size = std::mem::size_of::<u32>() as u32;

    let query_result = WinHttpQueryHeaders(
        h_request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        std::ptr::null(),
        &mut status_code as *mut u32 as *mut _,
        &mut status_code_size,
        std::ptr::null_mut(),
    );

    if query_result == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        return Err(anyhow!("WinHttpQueryHeaders failed"));
    }

    if status_code != 200 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        return Err(anyhow!("HTTP status {}", status_code));
    }

    let mut response_data = Vec::new();
    const READ_BUFFER_SIZE: usize = 4096;
    let mut buffer = [0u8; READ_BUFFER_SIZE];

    loop {
        let mut bytes_read: u32 = 0;

        let read_result = WinHttpReadData(
            h_request,
            buffer.as_mut_ptr() as *mut _,
            READ_BUFFER_SIZE as u32,
            &mut bytes_read,
        );

        if read_result == 0 {
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            return Err(anyhow!("WinHttpReadData failed"));
        }

        if bytes_read == 0 {
            break;
        }

        response_data.extend_from_slice(&buffer[..bytes_read as usize]);

        if response_data.len() > MAX_RESPONSE_SIZE {
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            return Err(anyhow!("response exceeded max size"));
        }
    }

    WinHttpCloseHandle(h_request);
    WinHttpCloseHandle(h_connect);

    Ok(response_data)
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    is_https: bool,
}

fn parse_url(url: &str) -> Result<ParsedUrl> {
    let is_https = url.starts_with("https://");
    let is_http = url.starts_with("http://");

    if !is_http && !is_https {
        return Err(anyhow!("URL must start with http:// or https://"));
    }

    let scheme_end = if is_https { 8 } else { 7 };
    let rest = &url[scheme_end..];

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let h = &host_port[..idx];
            let p_str = &host_port[idx + 1..];
            let p = p_str
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port"))?;
            (h, p)
        }
        None => {
            let default_port = if is_https { 443 } else { 80 };
            (host_port, default_port)
        }
    };

    Ok(ParsedUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
        is_https,
    })
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn parse_announce_response(data: &[u8]) -> Result<AnnounceResponse> {
    use nimble_bencode::decode::Value;

    let value = nimble_bencode::decode::decode(data)?;
    let dict = value
        .as_dict()
        .ok_or_else(|| anyhow!("tracker response must be dict"))?;

    if let Some(failure_val) = dict.get(b"failure reason".as_ref()) {
        let failure_str = failure_val
            .as_str()
            .ok_or_else(|| anyhow!("failure reason must be string"))?;

        return Ok(AnnounceResponse {
            interval: 0,
            complete: None,
            incomplete: None,
            peers: Vec::new(),
            failure_reason: Some(failure_str.to_string()),
        });
    }

    let interval = dict
        .get(b"interval".as_ref())
        .and_then(|v: &Value| v.as_integer())
        .ok_or_else(|| anyhow!("missing interval"))?;

    if interval <= 0 {
        return Err(anyhow!("interval must be positive"));
    }

    let complete = dict.get(b"complete".as_ref()).and_then(|v: &Value| {
        v.as_integer()
            .and_then(|i| if i >= 0 { Some(i as u32) } else { None })
    });

    let incomplete = dict.get(b"incomplete".as_ref()).and_then(|v: &Value| {
        v.as_integer()
            .and_then(|i| if i >= 0 { Some(i as u32) } else { None })
    });

    let peers = if let Some(peers_val) = dict.get(b"peers".as_ref()) {
        if let Some(peers_bytes) = peers_val.as_bytes() {
            parse_compact_peers(peers_bytes)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(AnnounceResponse {
        interval: interval as u32,
        complete,
        incomplete,
        peers,
        failure_reason: None,
    })
}

fn parse_compact_peers(data: &[u8]) -> Result<Vec<SocketAddrV4>> {
    if data.len() % 6 != 0 {
        return Err(anyhow!("compact peers length must be multiple of 6"));
    }

    let peer_count = data.len() / 6;
    let capped_count = peer_count.min(MAX_PEERS_FROM_TRACKER);
    let mut peers = Vec::with_capacity(capped_count);

    for chunk in data.chunks_exact(6).take(MAX_PEERS_FROM_TRACKER) {
        let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        peers.push(SocketAddrV4::new(ip, port));
    }

    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_http() {
        let parsed = parse_url("http://tracker.example.com:6969/announce").unwrap();
        assert_eq!(parsed.host, "tracker.example.com");
        assert_eq!(parsed.port, 6969);
        assert_eq!(parsed.path, "/announce");
        assert!(!parsed.is_https);
    }

    #[test]
    fn test_parse_url_https() {
        let parsed = parse_url("https://tracker.example.com/announce").unwrap();
        assert_eq!(parsed.host, "tracker.example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/announce");
        assert!(parsed.is_https);
    }

    #[test]
    fn test_parse_url_no_path() {
        let parsed = parse_url("http://example.com").unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path, "/");
    }

    #[test]
    fn test_build_query_string() {
        let info_hash = [0u8; 20];
        let peer_id = b"NIMBLE-0000000000000";

        let req = AnnounceRequest {
            info_hash: &info_hash,
            peer_id,
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1024,
            compact: true,
            event: TrackerEvent::Started,
        };

        let query = build_query_string(&req).unwrap();

        assert!(query.contains("info_hash="));
        assert!(query.contains("peer_id="));
        assert!(query.contains("port=6881"));
        assert!(query.contains("uploaded=0"));
        assert!(query.contains("downloaded=0"));
        assert!(query.contains("left=1024"));
        assert!(query.contains("compact=1"));
        assert!(query.contains("event=started"));
    }

    #[test]
    fn test_parse_compact_peers() {
        let data = vec![
            127, 0, 0, 1, 0x1A, 0xE1, // 127.0.0.1:6881
            192, 168, 1, 100, 0x1A, 0xE2, // 192.168.1.100:6882
        ];

        let peers = parse_compact_peers(&data).unwrap();

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].ip(), &Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(peers[0].port(), 6881);
        assert_eq!(peers[1].ip(), &Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(peers[1].port(), 6882);
    }

    #[test]
    fn test_parse_compact_peers_invalid_length() {
        let data = vec![127, 0, 0, 1, 0x1A];
        assert!(parse_compact_peers(&data).is_err());
    }

    #[test]
    fn test_parse_announce_response_with_failure() {
        let response = b"d14:failure reason19:torrent not allowede";
        let parsed = parse_announce_response(response).unwrap();

        assert!(parsed.failure_reason.is_some());
        assert_eq!(
            parsed.failure_reason.unwrap(),
            "torrent not allowed"
        );
    }

    #[test]
    fn test_parse_announce_response_success() {
        let response = b"d8:completei10e10:incompletei5e8:intervali1800e5:peers12:\x7f\x00\x00\x01\x1a\xe1\xc0\xa8\x01\x64\x1a\xe2e";
        let parsed = parse_announce_response(response).unwrap();

        assert!(parsed.failure_reason.is_none());
        assert_eq!(parsed.interval, 1800);
        assert_eq!(parsed.complete, Some(10));
        assert_eq!(parsed.incomplete, Some(5));
        assert_eq!(parsed.peers.len(), 2);
    }
}
