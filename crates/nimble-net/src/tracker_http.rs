use anyhow::{anyhow, Result};
use nimble_util::hash::percent_encode;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(not(windows))]
use std::io::Read;
#[cfg(not(windows))]
use std::thread;
#[cfg(not(windows))]
use std::time::Duration;
#[cfg(windows)]
use windows_sys::core::w;
#[cfg(windows)]
use windows_sys::Win32::Foundation::GetLastError;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinHttp::*;

use crate::peer_ip::{is_valid_peer_ip_v4, is_valid_peer_ip_v6};

const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB cap for tracker responses
const MAX_PEERS_FROM_TRACKER: usize = 200; // Cap peers to prevent excessive memory/CPU usage

const TIMEOUT_RESOLVE_MS: i32 = 30_000;
const TIMEOUT_CONNECT_MS: i32 = 30_000;
const TIMEOUT_SEND_MS: i32 = 30_000;
const TIMEOUT_RECEIVE_MS: i32 = 60_000;
const READ_BUFFER_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerEvent {
    Started,
    Stopped,
    Completed,
    None,
}

#[derive(Debug)]
pub enum HttpAnnounceEvent {
    Completed {
        request_id: u64,
        result: Result<AnnounceResponse>,
    },
}

pub struct TrackerContext {
    request_id: u64,
    sender: Sender<HttpAnnounceEvent>,
    response: Vec<u8>,
    read_buffer: [u8; READ_BUFFER_SIZE],
    h_request: *mut std::ffi::c_void,
    h_connect: *mut std::ffi::c_void,
    h_session: *mut std::ffi::c_void,
    completed: AtomicBool,
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
    pub peers6: Vec<SocketAddrV6>,
    pub failure_reason: Option<String>,
}

pub fn announce(base_url: &str, request: &AnnounceRequest) -> Result<AnnounceResponse> {
    static REQUEST_ID: AtomicU64 = AtomicU64::new(1);
    let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = std::sync::mpsc::channel();
    announce_async(base_url, request, request_id, tx)?;
    match rx.recv_timeout(std::time::Duration::from_secs(90)) {
        Ok(HttpAnnounceEvent::Completed { result, .. }) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(anyhow!("tracker announce timed out after 90 seconds"))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(anyhow!("tracker announce channel closed"))
        }
    }
}

pub fn announce_async(
    base_url: &str,
    request: &AnnounceRequest,
    request_id: u64,
    sender: Sender<HttpAnnounceEvent>,
) -> Result<()> {
    let query = build_query_string(request)?;
    let url = if base_url.contains('?') {
        format!("{}&{}", base_url, query)
    } else {
        format!("{}?{}", base_url, query)
    };

    http_get_async(&url, request_id, sender)
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

#[cfg(windows)]
fn http_get_async(url: &str, request_id: u64, sender: Sender<HttpAnnounceEvent>) -> Result<()> {
    unsafe {
        let h_session = WinHttpOpen(
            w!("Nimble/1.0"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_ASYNC,
        );

        if h_session.is_null() {
            return Err(anyhow!("WinHttpOpen failed"));
        }

        http_get_async_inner(h_session, url, request_id, sender)
    }
}

#[cfg(windows)]
unsafe fn http_get_async_inner(
    h_session: *mut std::ffi::c_void,
    url: &str,
    request_id: u64,
    sender: Sender<HttpAnnounceEvent>,
) -> Result<()> {
    let parsed = parse_url(url)?;

    let host_wide = to_wide(&parsed.host);
    let h_connect = WinHttpConnect(h_session, host_wide.as_ptr(), parsed.port, 0);

    if h_connect.is_null() {
        WinHttpCloseHandle(h_session);
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
        WinHttpCloseHandle(h_session);
        return Err(anyhow!("WinHttpOpenRequest failed"));
    }

    let mut context = Box::new(TrackerContext {
        request_id,
        sender,
        response: Vec::new(),
        read_buffer: [0u8; READ_BUFFER_SIZE],
        h_request,
        h_connect,
        h_session,
        completed: AtomicBool::new(false),
    });

    let context_ptr = Box::into_raw(context);
    let context_value = context_ptr as usize;
    let set_context = WinHttpSetOption(
        h_request,
        WINHTTP_OPTION_CONTEXT_VALUE,
        &context_value as *const usize as *mut _,
        std::mem::size_of::<usize>() as u32,
    );

    if set_context == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        drop(Box::from_raw(context_ptr));
        return Err(anyhow!("WinHttpSetOption context failed"));
    }

    let callback = WinHttpSetStatusCallback(
        h_request,
        Some(status_callback),
        WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
        0,
    );

    if callback.is_none() {
        let err = unsafe { GetLastError() };
        if err != 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        drop(Box::from_raw(context_ptr));
        return Err(anyhow!("WinHttpSetStatusCallback failed"));
        }
    }

    let timeout_result = WinHttpSetTimeouts(
        h_request,
        TIMEOUT_RESOLVE_MS,
        TIMEOUT_CONNECT_MS,
        TIMEOUT_SEND_MS,
        TIMEOUT_RECEIVE_MS,
    );

    if timeout_result == 0 {
        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);
        return Err(anyhow!("WinHttpSetTimeouts failed"));
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
        WinHttpCloseHandle(h_session);
        return Err(anyhow!("WinHttpSendRequest failed"));
    }

    Ok(())
}

#[cfg(windows)]
unsafe extern "system" fn status_callback(
    h_internet: *mut std::ffi::c_void,
    dw_context: usize,
    dw_internet_status: u32,
    lpv_status_information: *mut std::ffi::c_void,
    dw_status_information_length: u32,
) {
    let panic_result = std::panic::catch_unwind(|| {
        if dw_context == 0 {
            return;
        }

        let context_ptr = dw_context as *mut TrackerContext;
        let context = &mut *context_ptr;

        match dw_internet_status {
            WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE => {
                let _ = WinHttpReceiveResponse(h_internet, std::ptr::null_mut());
            }
            WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE => {
                let mut status_code: u32 = 0;
                let mut status_code_size = std::mem::size_of::<u32>() as u32;
                let query_result = WinHttpQueryHeaders(
                    h_internet,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    std::ptr::null(),
                    &mut status_code as *mut u32 as *mut _,
                    &mut status_code_size,
                    std::ptr::null_mut(),
                );

                if query_result == 0 {
                    complete_request(context_ptr, Err(anyhow!("WinHttpQueryHeaders failed")));
                    return;
                }

                if status_code != 200 {
                    complete_request(context_ptr, Err(anyhow!("HTTP status {}", status_code)));
                    return;
                }

                let _ = WinHttpQueryDataAvailable(h_internet, std::ptr::null_mut());
            }
            WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE => {
                if lpv_status_information.is_null() {
                    complete_request(context_ptr, Err(anyhow!("WinHTTP data available missing size")));
                    return;
                }

                let bytes_available = *(lpv_status_information as *const u32) as usize;
                if bytes_available == 0 {
                    let result = parse_announce_response(&context.response);
                    complete_request(context_ptr, result);
                    return;
                }

                if context.response.len() + bytes_available > MAX_RESPONSE_SIZE {
                    complete_request(context_ptr, Err(anyhow!("response exceeded max size")));
                    return;
                }

                let to_read = bytes_available.min(READ_BUFFER_SIZE);
                let _ = WinHttpReadData(
                    h_internet,
                    context.read_buffer.as_mut_ptr() as *mut _,
                    to_read as u32,
                    std::ptr::null_mut(),
                );
            }
            WINHTTP_CALLBACK_STATUS_READ_COMPLETE => {
                if dw_status_information_length == 0 {
                    let result = parse_announce_response(&context.response);
                    complete_request(context_ptr, result);
                    return;
                }

                let bytes_read = dw_status_information_length as usize;
                context
                    .response
                    .extend_from_slice(&context.read_buffer[..bytes_read]);

                if context.response.len() > MAX_RESPONSE_SIZE {
                    complete_request(context_ptr, Err(anyhow!("response exceeded max size")));
                    return;
                }

                let _ = WinHttpQueryDataAvailable(h_internet, std::ptr::null_mut());
            }
            WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
                if !lpv_status_information.is_null()
                    && dw_status_information_length as usize >= std::mem::size_of::<WINHTTP_ASYNC_RESULT>()
                {
                    let async_result = &*(lpv_status_information as *const WINHTTP_ASYNC_RESULT);
                    complete_request(
                        context_ptr,
                        Err(anyhow!("WinHTTP async error: {}", async_result.dwError)),
                    );
                } else {
                    complete_request(context_ptr, Err(anyhow!("WinHTTP async error")));
                }
            }
            WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING => {
                drop(Box::from_raw(context_ptr));
            }
            _ => {}
        }
    });

    if panic_result.is_err() {
        if dw_context != 0 && dw_internet_status != WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING {
            let context_ptr = dw_context as *mut TrackerContext;
            complete_request(context_ptr, Err(anyhow!("tracker response parsing panicked")));
        }
    }
}

#[cfg(windows)]
unsafe fn complete_request(context_ptr: *mut TrackerContext, result: Result<AnnounceResponse>) {
    let context = &mut *context_ptr;
    if context.completed.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = context.sender.send(HttpAnnounceEvent::Completed {
        request_id: context.request_id,
        result,
    });
    WinHttpCloseHandle(context.h_request);
    WinHttpCloseHandle(context.h_connect);
    WinHttpCloseHandle(context.h_session);
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

    let default_port = if is_https { 443 } else { 80 };
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| anyhow!("missing closing bracket in IPv6 host"))?;
        let host = &stripped[..end];
        let remainder = &stripped[end + 1..];
        if remainder.is_empty() {
            (host, default_port)
        } else if let Some(port_str) = remainder.strip_prefix(':') {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port"))?;
            (host, port)
        } else {
            return Err(anyhow!("invalid IPv6 host/port"));
        }
    } else if let Some((host, port_str)) = host_port.rsplit_once(':') {
        if host.contains(':') {
            return Err(anyhow!("IPv6 hosts must be bracketed"));
        }
        let port = port_str
            .parse::<u16>()
            .map_err(|_| anyhow!("invalid port"))?;
        (host, port)
    } else {
        (host_port, default_port)
    };

    if host.is_empty() {
        return Err(anyhow!("missing host"));
    }

    Ok(ParsedUrl {
        host: host.to_string(),
        port,
        path: path.to_string(),
        is_https,
    })
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn http_get_async(url: &str, request_id: u64, sender: Sender<HttpAnnounceEvent>) -> Result<()> {
    let url = url.to_string();
    thread::spawn(move || {
        let result = http_get_sync(&url);
        let _ = sender.send(HttpAnnounceEvent::Completed { request_id, result });
    });
    Ok(())
}

#[cfg(not(windows))]
fn http_get_sync(url: &str) -> Result<AnnounceResponse> {
    if url.starts_with("https://") {
        return Err(anyhow!("HTTPS trackers require WinHTTP on Windows builds"));
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(TIMEOUT_CONNECT_MS as u64))
        .timeout_read(Duration::from_millis(TIMEOUT_RECEIVE_MS as u64))
        .build();

    let response = agent.get(url).call().map_err(|err| anyhow!(err))?;
    if response.status() != 200 {
        return Err(anyhow!("HTTP status {}", response.status()));
    }

    let mut reader = response.into_reader();
    let mut buffer = Vec::new();
    let mut chunk = [0u8; READ_BUFFER_SIZE];

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        if buffer.len() + read > MAX_RESPONSE_SIZE {
            return Err(anyhow!("response exceeded max size"));
        }

        buffer.extend_from_slice(&chunk[..read]);
    }

    parse_announce_response(&buffer)
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
            peers6: Vec::new(),
            failure_reason: Some(failure_str.to_string()),
        });
    }

    let interval = dict
        .get(b"interval".as_ref())
        .and_then(|v: &Value| v.as_integer())
        .ok_or_else(|| anyhow!("missing interval"))?;

    if interval <= 0 || interval > u32::MAX as i64 {
        return Err(anyhow!("interval out of valid range"));
    }

    let complete = dict.get(b"complete".as_ref()).and_then(|v: &Value| {
        v.as_integer()
            .and_then(|i| if i >= 0 && i <= u32::MAX as i64 { Some(i as u32) } else { None })
    });

    let incomplete = dict.get(b"incomplete".as_ref()).and_then(|v: &Value| {
        v.as_integer()
            .and_then(|i| if i >= 0 && i <= u32::MAX as i64 { Some(i as u32) } else { None })
    });

    let peers = if let Some(peers_val) = dict.get(b"peers".as_ref()) {
        if let Some(peers_bytes) = peers_val.as_bytes() {
            parse_compact_peers(peers_bytes)?
        } else if let Some(peers_list) = peers_val.as_list() {
            parse_dict_peers(peers_list)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let peers6 = if let Some(peers6_val) = dict.get(b"peers6".as_ref()) {
        if let Some(peers6_bytes) = peers6_val.as_bytes() {
            parse_compact_peers6(peers6_bytes)?
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
        peers6,
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
        if !is_valid_peer_ip_v4(&ip) {
            continue;
        }
        peers.push(SocketAddrV4::new(ip, port));
    }

    Ok(peers)
}

fn parse_compact_peers6(data: &[u8]) -> Result<Vec<SocketAddrV6>> {
    if data.len() % 18 != 0 {
        return Err(anyhow!("compact peers6 length must be multiple of 18"));
    }

    let peer_count = data.len() / 18;
    let capped_count = peer_count.min(MAX_PEERS_FROM_TRACKER);
    let mut peers = Vec::with_capacity(capped_count);

    for chunk in data.chunks_exact(18).take(MAX_PEERS_FROM_TRACKER) {
        let ip = Ipv6Addr::from([
            chunk[0], chunk[1], chunk[2], chunk[3],
            chunk[4], chunk[5], chunk[6], chunk[7],
            chunk[8], chunk[9], chunk[10], chunk[11],
            chunk[12], chunk[13], chunk[14], chunk[15],
        ]);
        let port = u16::from_be_bytes([chunk[16], chunk[17]]);
        if !is_valid_peer_ip_v6(&ip) {
            continue;
        }
        peers.push(SocketAddrV6::new(ip, port, 0, 0));
    }

    Ok(peers)
}

fn parse_dict_peers(peers_list: &[nimble_bencode::decode::Value]) -> Result<Vec<SocketAddrV4>> {
    let mut peers = Vec::with_capacity(peers_list.len().min(MAX_PEERS_FROM_TRACKER));

    for peer_val in peers_list.iter().take(MAX_PEERS_FROM_TRACKER) {
        if let Some(peer_dict) = peer_val.as_dict() {
            let ip_val = peer_dict.get(b"ip".as_ref());
            let port_val = peer_dict.get(b"port".as_ref());

            if let (Some(ip_str), Some(port_int)) = (
                ip_val.and_then(|v| v.as_str()),
                port_val.and_then(|v| v.as_integer()),
            ) {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if port_int > 0 && port_int <= u16::MAX as i64 {
                        if !is_valid_peer_ip_v4(&ip) {
                            continue;
                        }
                        peers.push(SocketAddrV4::new(ip, port_int as u16));
                    }
                }
            }
        }
    }

    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimble_bencode::decode::Value;
    use std::collections::BTreeMap;

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
    fn test_parse_url_ipv6_with_port() {
        let parsed = parse_url("http://[2001:db8::1]:6969/announce").unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 6969);
        assert_eq!(parsed.path, "/announce");
        assert!(!parsed.is_https);
    }

    #[test]
    fn test_parse_url_ipv6_no_port() {
        let parsed = parse_url("https://[2001:db8::1]/announce").unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/announce");
        assert!(parsed.is_https);
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
            10, 0, 0, 1, 0x1A, 0xE1, // 10.0.0.1:6881
            8, 8, 8, 8, 0x1A, 0xE2, // 8.8.8.8:6882
        ];

        let peers = parse_compact_peers(&data).unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip(), &Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(peers[0].port(), 6882);
    }

    #[test]
    fn test_parse_compact_peers_invalid_length() {
        let data = vec![127, 0, 0, 1, 0x1A];
        assert!(parse_compact_peers(&data).is_err());
    }

    #[test]
    fn test_parse_dict_peers_filters_private_ips() {
        let mut private_peer = BTreeMap::new();
        private_peer.insert(b"ip".as_ref(), Value::ByteString(b"192.168.1.10"));
        private_peer.insert(b"port".as_ref(), Value::Integer(6881));

        let mut public_peer = BTreeMap::new();
        public_peer.insert(b"ip".as_ref(), Value::ByteString(b"1.1.1.1"));
        public_peer.insert(b"port".as_ref(), Value::Integer(6882));

        let peers_list = vec![Value::Dict(private_peer), Value::Dict(public_peer)];

        let peers = parse_dict_peers(&peers_list).unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip(), &Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(peers[0].port(), 6882);
    }

    #[test]
    fn test_parse_compact_peers6_filters_private_ips() {
        let mut data = Vec::new();
        data.extend_from_slice(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).octets());
        data.extend_from_slice(&6881u16.to_be_bytes());
        data.extend_from_slice(
            &Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).octets(),
        );
        data.extend_from_slice(&6882u16.to_be_bytes());

        let peers = parse_compact_peers6(&data).unwrap();

        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].ip(),
            &Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)
        );
        assert_eq!(peers[0].port(), 6882);
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
        let response = b"d8:completei10e10:incompletei5e8:intervali1800e5:peers12:\x0a\x00\x00\x01\x1a\xe1\x01\x01\x01\x01\x1a\xe2e";
        let parsed = parse_announce_response(response).unwrap();

        assert!(parsed.failure_reason.is_none());
        assert_eq!(parsed.interval, 1800);
        assert_eq!(parsed.complete, Some(10));
        assert_eq!(parsed.incomplete, Some(5));
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].ip(), &Ipv4Addr::new(1, 1, 1, 1));
    }
}
