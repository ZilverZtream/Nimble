use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use crate::encryption::{MseHandshake, MseStage, MSE_KEY_LENGTH};
    use std::net::SocketAddrV6;
    use windows_sys::Win32::Networking::WinSock::{
        self, AF_INET, AF_INET6, FD_SET, FIONBIO, INVALID_SOCKET, IPPROTO_TCP, IPPROTO_IPV6,
        SOCKADDR_IN, SOCKADDR_IN6, SOCKET, SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR,
        TIMEVAL, WSADATA, IPV6_V6ONLY,
    };

    const MAX_PENDING_HANDSHAKES: usize = 32;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const PROTOCOL_STRING: &[u8] = b"BitTorrent protocol";
    const PROTOCOL_STRING_LENGTH: u8 = 19;
    const HANDSHAKE_LENGTH: usize = 68;
    const MSE_VC_LENGTH: usize = 8;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAEINPROGRESS: i32 = 10036;
    const MAX_MSE_INFOHASH_ATTEMPTS: usize = 8;

    struct SafeSocket(SOCKET);

    impl SafeSocket {
        fn new(socket: SOCKET) -> Result<Self> {
            if socket == INVALID_SOCKET {
                return Err(anyhow!("invalid socket"));
            }
            Ok(SafeSocket(socket))
        }

        fn raw(&self) -> SOCKET {
            self.0
        }

        fn into_raw(self) -> SOCKET {
            let socket = self.0;
            std::mem::forget(self);
            socket
        }
    }

    impl Drop for SafeSocket {
        fn drop(&mut self) {
            if self.0 != INVALID_SOCKET {
                unsafe {
                    WinSock::closesocket(self.0);
                }
            }
        }
    }

    pub struct PeerListener {
        socket_v4: SOCKET,
        socket_v6: SOCKET,
        port: u16,
        pending: HashMap<SOCKET, PendingHandshake>,
        infohash_registry: HashMap<[u8; 20], InfoHashEntry>,
    }

    struct PendingHandshake {
        socket: SOCKET,
        addr: SocketAddr,
        started_at: Instant,
        recv_buffer: Vec<u8>,
        mse_state: Option<MseState>,
        force_mse: bool,
    }

    enum MseState {
        AwaitingVc {
            base: MseHandshake,
            peer_pubkey: Vec<u8>,
        },
        AwaitingHandshake {
            mse: MseHandshake,
            info_hash: [u8; 20],
            our_peer_id: [u8; 20],
        },
    }

    struct InfoHashEntry {
        peer_id: [u8; 20],
        piece_count: usize,
    }

    pub struct AcceptedPeer {
        pub socket: SOCKET,
        pub addr: SocketAddr,
        pub info_hash: [u8; 20],
        pub their_peer_id: [u8; 20],
        pub mse_handshake: Option<MseHandshake>,
    }

    impl PeerListener {
        pub fn new(port: u16) -> Result<Self> {
            init_winsock()?;

            let raw_socket = unsafe { WinSock::socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
            let socket_v4 = SafeSocket::new(raw_socket)?;

            let enable: i32 = 1;
            unsafe {
                WinSock::setsockopt(
                    socket_v4.raw(),
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    &enable as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            let sockaddr_v4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: port.to_be(),
                sin_addr: WinSock::IN_ADDR {
                    S_un: WinSock::IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(Ipv4Addr::UNSPECIFIED.octets()),
                    },
                },
                sin_zero: [0; 8],
            };

            let bind_result = unsafe {
                WinSock::bind(
                    socket_v4.raw(),
                    &sockaddr_v4 as *const SOCKADDR_IN as *const WinSock::SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };

            if bind_result == SOCKET_ERROR {
                return Err(anyhow!("bind() failed: {}", get_last_error()));
            }

            let assigned_port = if port == 0 {
                get_bound_port_v4(socket_v4.raw())?
            } else {
                port
            };

            let raw_socket_v6 = unsafe { WinSock::socket(AF_INET6 as i32, SOCK_STREAM, IPPROTO_TCP) };
            let socket_v6 = SafeSocket::new(raw_socket_v6)?;

            unsafe {
                WinSock::setsockopt(
                    socket_v6.raw(),
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    &enable as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            let v6_only: i32 = 1;
            unsafe {
                WinSock::setsockopt(
                    socket_v6.raw(),
                    IPPROTO_IPV6 as i32,
                    IPV6_V6ONLY as i32,
                    &v6_only as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            let sockaddr_v6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: assigned_port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: WinSock::IN6_ADDR {
                    u: WinSock::IN6_ADDR_0 { Byte: [0; 16] },
                },
                sin6_scope_id: 0,
            };

            let bind_v6_result = unsafe {
                WinSock::bind(
                    socket_v6.raw(),
                    &sockaddr_v6 as *const SOCKADDR_IN6 as *const WinSock::SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN6>() as i32,
                )
            };

            if bind_v6_result == SOCKET_ERROR {
                return Err(anyhow!("bind(v6) failed: {}", get_last_error()));
            }

            let listen_result = unsafe { WinSock::listen(socket_v4.raw(), 16) };
            if listen_result == SOCKET_ERROR {
                return Err(anyhow!("listen(v4) failed: {}", get_last_error()));
            }

            let listen_v6_result = unsafe { WinSock::listen(socket_v6.raw(), 16) };
            if listen_v6_result == SOCKET_ERROR {
                return Err(anyhow!("listen(v6) failed: {}", get_last_error()));
            }

            set_nonblocking(socket_v4.raw())?;
            set_nonblocking(socket_v6.raw())?;

            Ok(PeerListener {
                socket_v4: socket_v4.into_raw(),
                socket_v6: socket_v6.into_raw(),
                port: assigned_port,
                pending: HashMap::new(),
                infohash_registry: HashMap::new(),
            })
        }

        pub fn register_infohash(&mut self, info_hash: [u8; 20], peer_id: [u8; 20], piece_count: usize) {
            self.infohash_registry.insert(
                info_hash,
                InfoHashEntry {
                    peer_id,
                    piece_count,
                },
            );
        }

        pub fn unregister_infohash(&mut self, info_hash: &[u8; 20]) {
            self.infohash_registry.remove(info_hash);
        }

        pub fn port(&self) -> u16 {
            self.port
        }

        pub fn poll(&mut self) -> Result<Vec<AcceptedPeer>> {
            let mut accepted = Vec::new();

            self.accept_new_connections()?;
            self.process_pending_handshakes(&mut accepted)?;
            self.cleanup_timed_out();

            Ok(accepted)
        }

        fn accept_new_connections(&mut self) -> Result<()> {
            loop {
                if self.pending.len() >= MAX_PENDING_HANDSHAKES {
                    break;
                }

                let mut accepted_any = false;
                if let Some((client, peer_addr)) = self.accept_v4()? {
                    self.insert_pending(client, peer_addr);
                    accepted_any = true;
                }

                if self.pending.len() >= MAX_PENDING_HANDSHAKES {
                    break;
                }

                if let Some((client, peer_addr)) = self.accept_v6()? {
                    self.insert_pending(client, peer_addr);
                    accepted_any = true;
                }

                if !accepted_any {
                    break;
                }
            }

            Ok(())
        }

        fn accept_v4(&self) -> Result<Option<(SOCKET, SocketAddr)>> {
            let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<SOCKADDR_IN>() as i32;

            let client = unsafe {
                WinSock::accept(
                    self.socket_v4,
                    &mut addr as *mut SOCKADDR_IN as *mut WinSock::SOCKADDR,
                    &mut addr_len,
                )
            };

            if client == INVALID_SOCKET {
                let err = get_last_error();
                if err != WSAEWOULDBLOCK && err != WSAEINPROGRESS {
                    return Err(anyhow!("accept(v4) failed: {}", err));
                }
                return Ok(None);
            }

            set_nonblocking(client)?;

            let ip_bytes = unsafe { addr.sin_addr.S_un.S_addr.to_ne_bytes() };
            let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            let port = u16::from_be(addr.sin_port);
            let peer_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

            Ok(Some((client, peer_addr)))
        }

        fn accept_v6(&self) -> Result<Option<(SOCKET, SocketAddr)>> {
            let mut addr: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<SOCKADDR_IN6>() as i32;

            let client = unsafe {
                WinSock::accept(
                    self.socket_v6,
                    &mut addr as *mut SOCKADDR_IN6 as *mut WinSock::SOCKADDR,
                    &mut addr_len,
                )
            };

            if client == INVALID_SOCKET {
                let err = get_last_error();
                if err != WSAEWOULDBLOCK && err != WSAEINPROGRESS {
                    return Err(anyhow!("accept(v6) failed: {}", err));
                }
                return Ok(None);
            }

            set_nonblocking(client)?;

            let ip_bytes = unsafe { addr.sin6_addr.u.Byte };
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be(addr.sin6_port);
            let peer_addr = SocketAddr::V6(SocketAddrV6::new(ip, port, addr.sin6_flowinfo, addr.sin6_scope_id));

            Ok(Some((client, peer_addr)))
        }

        fn insert_pending(&mut self, client: SOCKET, peer_addr: SocketAddr) {
            self.pending.insert(
                client,
                PendingHandshake {
                    socket: client,
                    addr: peer_addr,
                    started_at: Instant::now(),
                    recv_buffer: Vec::with_capacity(HANDSHAKE_LENGTH),
                    mse_state: None,
                    force_mse: false,
                },
            );
        }

        fn process_pending_handshakes(&mut self, accepted: &mut Vec<AcceptedPeer>) -> Result<()> {
            let mut completed = Vec::new();
            let mut failed = Vec::new();
            let registry = &self.infohash_registry;

            for (&sock, pending) in self.pending.iter_mut() {
                if pending.mse_state.is_none() {
                    let target_len = match pending.recv_buffer.first().copied() {
                        Some(PROTOCOL_STRING_LENGTH) if !pending.force_mse => HANDSHAKE_LENGTH,
                        Some(_) => MSE_KEY_LENGTH,
                        None => HANDSHAKE_LENGTH,
                    };

                    let remaining = target_len.saturating_sub(pending.recv_buffer.len());
                    if remaining > 0 {
                        let mut buf = [0u8; MSE_KEY_LENGTH];
                        let read_len = remaining.min(MSE_KEY_LENGTH);
                        let n = unsafe {
                            WinSock::recv(sock, buf.as_mut_ptr(), read_len as i32, 0)
                        };

                        if n > 0 {
                            pending.recv_buffer.extend_from_slice(&buf[..n as usize]);
                        } else if n == 0 {
                            failed.push(sock);
                            continue;
                        } else {
                            let err = get_last_error();
                            if err != WSAEWOULDBLOCK && err != WSAEINPROGRESS {
                                failed.push(sock);
                            }
                            continue;
                        }
                    }

                    if pending.recv_buffer.len() >= target_len {
                        if pending.recv_buffer.first().copied() == Some(PROTOCOL_STRING_LENGTH) && !pending.force_mse {
                            if pending.recv_buffer.len() >= HANDSHAKE_LENGTH
                                && &pending.recv_buffer[1..20] == PROTOCOL_STRING
                            {
                                match Self::validate_and_respond_plain(registry, sock, pending) {
                                    Ok(peer) => completed.push((sock, peer)),
                                    Err(_) => failed.push(sock),
                                }
                                continue;
                            }
                            pending.force_mse = true;
                        }

                        if pending.recv_buffer.len() >= MSE_KEY_LENGTH {
                            let peer_pubkey = pending.recv_buffer.drain(..MSE_KEY_LENGTH).collect();
                            let base = MseHandshake::new_responder();
                            let sent = unsafe {
                                WinSock::send(
                                    sock,
                                    base.get_public_key().as_ptr(),
                                    base.get_public_key().len() as i32,
                                    0,
                                )
                            };
                            if sent != MSE_KEY_LENGTH as i32 {
                                failed.push(sock);
                                continue;
                            }
                            pending.mse_state = Some(MseState::AwaitingVc { base, peer_pubkey });
                        }
                    }
                }

                if pending.mse_state.is_some() {
                    match Self::process_mse_handshake(registry, sock, pending) {
                        Ok(Some(peer)) => completed.push((sock, peer)),
                        Ok(None) => {}
                        Err(_) => failed.push(sock),
                    }
                }
            }

            for sock in failed {
                if let Some(pending) = self.pending.remove(&sock) {
                    unsafe {
                        WinSock::closesocket(pending.socket);
                    }
                }
            }

            for (sock, peer) in completed {
                self.pending.remove(&sock);
                accepted.push(peer);
            }

            Ok(())
        }

        fn validate_and_respond_plain(
            registry: &HashMap<[u8; 20], InfoHashEntry>,
            sock: SOCKET,
            pending: &PendingHandshake,
        ) -> Result<AcceptedPeer> {
            let data = &pending.recv_buffer;

            if data[0] != PROTOCOL_STRING_LENGTH {
                return Err(anyhow!("invalid protocol string length"));
            }

            if &data[1..20] != PROTOCOL_STRING {
                return Err(anyhow!("invalid protocol string"));
            }

            let their_info_hash: [u8; 20] = data[28..48]
                .try_into()
                .map_err(|_| anyhow!("invalid info hash length"))?;
            let their_peer_id: [u8; 20] = data[48..68]
                .try_into()
                .map_err(|_| anyhow!("invalid peer id length"))?;

            let entry = registry
                .get(&their_info_hash)
                .ok_or_else(|| anyhow!("unknown infohash"))?;

            let mut response = Vec::with_capacity(HANDSHAKE_LENGTH);
            response.push(PROTOCOL_STRING_LENGTH);
            response.extend_from_slice(PROTOCOL_STRING);

            let mut reserved = [0u8; 8];
            reserved[5] |= 0x10;
            response.extend_from_slice(&reserved);

            response.extend_from_slice(&their_info_hash);
            response.extend_from_slice(&entry.peer_id);

            let sent = unsafe {
                WinSock::send(sock, response.as_ptr(), response.len() as i32, 0)
            };

            if sent != HANDSHAKE_LENGTH as i32 {
                return Err(anyhow!("failed to send handshake response"));
            }

            Ok(AcceptedPeer {
                socket: sock,
                addr: pending.addr,
                info_hash: their_info_hash,
                their_peer_id,
                mse_handshake: None,
            })
        }

        fn process_mse_handshake(
            registry: &HashMap<[u8; 20], InfoHashEntry>,
            sock: SOCKET,
            pending: &mut PendingHandshake,
        ) -> Result<Option<AcceptedPeer>> {
            match pending.mse_state.take() {
                Some(MseState::AwaitingVc { base, peer_pubkey }) => {
                    if pending.recv_buffer.len() < MSE_VC_LENGTH {
                        let remaining = MSE_VC_LENGTH - pending.recv_buffer.len();
                        let mut buf = [0u8; MSE_VC_LENGTH];
                        let n = unsafe {
                            WinSock::recv(sock, buf.as_mut_ptr(), remaining as i32, 0)
                        };

                        if n > 0 {
                            pending.recv_buffer.extend_from_slice(&buf[..n as usize]);
                        } else if n == 0 {
                            return Err(anyhow!("connection closed"));
                        } else {
                            let err = get_last_error();
                            if err != WSAEWOULDBLOCK && err != WSAEINPROGRESS {
                                return Err(anyhow!("recv failed: {}", err));
                            }
                            pending.mse_state = Some(MseState::AwaitingVc { base, peer_pubkey });
                            return Ok(None);
                        }
                    }

                    if pending.recv_buffer.len() < MSE_VC_LENGTH {
                        pending.mse_state = Some(MseState::AwaitingVc { base, peer_pubkey });
                        return Ok(None);
                    }

                    let encrypted_vc: Vec<u8> = pending.recv_buffer.drain(..MSE_VC_LENGTH).collect();

                    let Some((info_hash, our_peer_id, mut mse)) =
                        Self::select_mse_handshake(registry, &base, &peer_pubkey, &encrypted_vc)
                    else {
                        return Err(anyhow!("unable to resolve MSE infohash"));
                    };

                    let mut vc = [0u8; MSE_VC_LENGTH];
                    mse.encrypt(&mut vc);
                    let sent = unsafe {
                        WinSock::send(sock, vc.as_ptr(), vc.len() as i32, 0)
                    };
                    if sent != MSE_VC_LENGTH as i32 {
                        return Err(anyhow!("failed to send MSE verification constant"));
                    }

                    mse.set_stage(MseStage::Established);
                    pending.mse_state = Some(MseState::AwaitingHandshake { mse, info_hash, our_peer_id });
                    Ok(None)
                }
                Some(MseState::AwaitingHandshake { mut mse, info_hash, our_peer_id }) => {
                    if pending.recv_buffer.len() < HANDSHAKE_LENGTH {
                        let remaining = HANDSHAKE_LENGTH - pending.recv_buffer.len();
                        let mut buf = [0u8; HANDSHAKE_LENGTH];
                        let n = unsafe {
                            WinSock::recv(sock, buf.as_mut_ptr(), remaining as i32, 0)
                        };

                        if n > 0 {
                            pending.recv_buffer.extend_from_slice(&buf[..n as usize]);
                        } else if n == 0 {
                            return Err(anyhow!("connection closed"));
                        } else {
                            let err = get_last_error();
                            if err != WSAEWOULDBLOCK && err != WSAEINPROGRESS {
                                return Err(anyhow!("recv failed: {}", err));
                            }
                            pending.mse_state = Some(MseState::AwaitingHandshake { mse, info_hash, our_peer_id });
                            return Ok(None);
                        }
                    }

                    if pending.recv_buffer.len() < HANDSHAKE_LENGTH {
                        pending.mse_state = Some(MseState::AwaitingHandshake { mse, info_hash, our_peer_id });
                        return Ok(None);
                    }

                    let mut handshake: Vec<u8> = pending.recv_buffer.drain(..HANDSHAKE_LENGTH).collect();
                    mse.decrypt(&mut handshake);

                    if handshake[0] != PROTOCOL_STRING_LENGTH {
                        return Err(anyhow!("invalid protocol string length"));
                    }

                    if &handshake[1..20] != PROTOCOL_STRING {
                        return Err(anyhow!("invalid protocol string"));
                    }

                    let their_info_hash: [u8; 20] = handshake[28..48]
                        .try_into()
                        .map_err(|_| anyhow!("invalid info hash length"))?;
                    let their_peer_id: [u8; 20] = handshake[48..68]
                        .try_into()
                        .map_err(|_| anyhow!("invalid peer id length"))?;

                    if their_info_hash != info_hash {
                        return Err(anyhow!("info hash mismatch"));
                    }

                    let mut response = Vec::with_capacity(HANDSHAKE_LENGTH);
                    response.push(PROTOCOL_STRING_LENGTH);
                    response.extend_from_slice(PROTOCOL_STRING);

                    let mut reserved = [0u8; 8];
                    reserved[5] |= 0x10;
                    response.extend_from_slice(&reserved);

                    response.extend_from_slice(&info_hash);
                    response.extend_from_slice(&our_peer_id);

                    mse.encrypt(&mut response);
                    let sent = unsafe {
                        WinSock::send(sock, response.as_ptr(), response.len() as i32, 0)
                    };

                    if sent != HANDSHAKE_LENGTH as i32 {
                        return Err(anyhow!("failed to send encrypted handshake response"));
                    }

                    Ok(Some(AcceptedPeer {
                        socket: sock,
                        addr: pending.addr,
                        info_hash,
                        their_peer_id,
                        mse_handshake: Some(mse),
                    }))
                }
                None => Ok(None),
            }
        }

        fn select_mse_handshake(
            registry: &HashMap<[u8; 20], InfoHashEntry>,
            base: &MseHandshake,
            peer_pubkey: &[u8],
            encrypted_vc: &[u8],
        ) -> Option<([u8; 20], [u8; 20], MseHandshake)> {
            let mut attempts = 0;
            for (info_hash, entry) in registry.iter() {
                if attempts >= MAX_MSE_INFOHASH_ATTEMPTS {
                    break;
                }
                attempts += 1;

                let mut candidate = base.clone_without_ciphers();
                if candidate.compute_shared_secret(peer_pubkey, info_hash).is_err() {
                    continue;
                }
                let mut vc = encrypted_vc.to_vec();
                candidate.decrypt(&mut vc);
                if vc == [0u8; MSE_VC_LENGTH] {
                    return Some((*info_hash, entry.peer_id, candidate));
                }
            }
            None
        }

        fn cleanup_timed_out(&mut self) {
            let timed_out: Vec<SOCKET> = self
                .pending
                .iter()
                .filter(|(_, p)| p.started_at.elapsed() > HANDSHAKE_TIMEOUT)
                .map(|(&s, _)| s)
                .collect();

            for sock in timed_out {
                if let Some(pending) = self.pending.remove(&sock) {
                    unsafe {
                        WinSock::closesocket(pending.socket);
                    }
                }
            }
        }

        pub fn close(&mut self) {
            for (_, pending) in self.pending.drain() {
                unsafe {
                    WinSock::closesocket(pending.socket);
                }
            }

            if self.socket_v4 != INVALID_SOCKET {
                unsafe {
                    WinSock::closesocket(self.socket_v4);
                }
                self.socket_v4 = INVALID_SOCKET;
            }

            if self.socket_v6 != INVALID_SOCKET {
                unsafe {
                    WinSock::closesocket(self.socket_v6);
                }
                self.socket_v6 = INVALID_SOCKET;
            }
        }
    }

    impl Drop for PeerListener {
        fn drop(&mut self) {
            self.close();
        }
    }

    fn set_nonblocking(socket: SOCKET) -> Result<()> {
        let mut mode: u32 = 1;
        let result = unsafe { WinSock::ioctlsocket(socket, FIONBIO as i32, &mut mode) };

        if result == SOCKET_ERROR {
            return Err(anyhow!("ioctlsocket(FIONBIO) failed: {}", get_last_error()));
        }
        Ok(())
    }

    fn get_last_error() -> i32 {
        unsafe { WinSock::WSAGetLastError() }
    }

    fn get_bound_port_v4(socket: SOCKET) -> Result<u16> {
        let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<SOCKADDR_IN>() as i32;
        let result = unsafe {
            WinSock::getsockname(
                socket,
                &mut addr as *mut SOCKADDR_IN as *mut WinSock::SOCKADDR,
                &mut len,
            )
        };
        if result == SOCKET_ERROR {
            return Err(anyhow!("getsockname() failed: {}", get_last_error()));
        }
        Ok(u16::from_be(addr.sin_port))
    }

    static WINSOCK_INIT: std::sync::Once = std::sync::Once::new();

    fn init_winsock() -> Result<()> {
        static mut INIT_RESULT: Option<i32> = None;

        WINSOCK_INIT.call_once(|| {
            let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
            let result = unsafe { WinSock::WSAStartup(0x0202, &mut wsa_data) };
            unsafe {
                INIT_RESULT = Some(result);
            }
        });

        unsafe {
            if let Some(result) = INIT_RESULT {
                if result != 0 {
                    return Err(anyhow!("WSAStartup failed: {}", result));
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
mod unix_impl {
    use super::*;
    use crate::encryption::{MseHandshake, MseStage, MSE_KEY_LENGTH};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::FromRawFd;

    const MAX_PENDING_HANDSHAKES: usize = 32;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const PROTOCOL_STRING: &[u8] = b"BitTorrent protocol";
    const PROTOCOL_STRING_LENGTH: u8 = 19;
    const HANDSHAKE_LENGTH: usize = 68;
    const MSE_VC_LENGTH: usize = 8;
    const MAX_MSE_INFOHASH_ATTEMPTS: usize = 8;

    pub struct PeerListener {
        listener_v4: TcpListener,
        listener_v6: TcpListener,
        port: u16,
        pending: HashMap<usize, PendingHandshake>,
        infohash_registry: HashMap<[u8; 20], InfoHashEntry>,
        next_id: usize,
    }

    struct PendingHandshake {
        stream: TcpStream,
        addr: SocketAddr,
        started_at: Instant,
        recv_buffer: Vec<u8>,
        mse_state: Option<MseState>,
        force_mse: bool,
    }

    enum MseState {
        AwaitingVc {
            base: MseHandshake,
            peer_pubkey: Vec<u8>,
        },
        AwaitingHandshake {
            mse: MseHandshake,
            info_hash: [u8; 20],
            our_peer_id: [u8; 20],
        },
    }

    struct InfoHashEntry {
        peer_id: [u8; 20],
        piece_count: usize,
    }

    pub struct AcceptedPeer {
        pub stream: TcpStream,
        pub addr: SocketAddr,
        pub info_hash: [u8; 20],
        pub their_peer_id: [u8; 20],
        pub mse_handshake: Option<MseHandshake>,
    }

    impl PeerListener {
        pub fn new(port: u16) -> Result<Self> {
            let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
            let listener_v4 = TcpListener::bind(addr)?;
            listener_v4.set_nonblocking(true)?;
            let assigned_port = listener_v4.local_addr()?.port();
            let listener_v6 = bind_v6_listener(assigned_port)?;
            listener_v6.set_nonblocking(true)?;

            Ok(PeerListener {
                listener_v4,
                listener_v6,
                port: assigned_port,
                pending: HashMap::new(),
                infohash_registry: HashMap::new(),
                next_id: 0,
            })
        }

        pub fn register_infohash(&mut self, info_hash: [u8; 20], peer_id: [u8; 20], piece_count: usize) {
            self.infohash_registry.insert(
                info_hash,
                InfoHashEntry {
                    peer_id,
                    piece_count,
                },
            );
        }

        pub fn unregister_infohash(&mut self, info_hash: &[u8; 20]) {
            self.infohash_registry.remove(info_hash);
        }

        pub fn port(&self) -> u16 {
            self.port
        }

        pub fn poll(&mut self) -> Result<Vec<AcceptedPeer>> {
            let mut accepted = Vec::new();

            self.accept_new_connections()?;
            self.process_pending_handshakes(&mut accepted)?;
            self.cleanup_timed_out();

            Ok(accepted)
        }

        fn accept_new_connections(&mut self) -> Result<()> {
            loop {
                if self.pending.len() >= MAX_PENDING_HANDSHAKES {
                    break;
                }

                let mut accepted_any = false;
                if let Some((stream, addr)) = accept_stream(&self.listener_v4)? {
                    self.insert_pending(stream, addr);
                    accepted_any = true;
                }

                if self.pending.len() >= MAX_PENDING_HANDSHAKES {
                    break;
                }

                if let Some((stream, addr)) = accept_stream(&self.listener_v6)? {
                    self.insert_pending(stream, addr);
                    accepted_any = true;
                }

                if !accepted_any {
                    break;
                }
            }
            Ok(())
        }

        fn insert_pending(&mut self, stream: TcpStream, addr: SocketAddr) {
            let id = self.next_id;
            self.next_id += 1;
            self.pending.insert(
                id,
                PendingHandshake {
                    stream,
                    addr,
                    started_at: Instant::now(),
                    recv_buffer: Vec::with_capacity(HANDSHAKE_LENGTH),
                    mse_state: None,
                    force_mse: false,
                },
            );
        }

        fn process_pending_handshakes(&mut self, accepted: &mut Vec<AcceptedPeer>) -> Result<()> {
            let mut completed = Vec::new();
            let mut failed = Vec::new();
            let registry = &self.infohash_registry;

            for (&id, pending) in self.pending.iter_mut() {
                if pending.mse_state.is_none() {
                    let target_len = match pending.recv_buffer.first().copied() {
                        Some(PROTOCOL_STRING_LENGTH) if !pending.force_mse => HANDSHAKE_LENGTH,
                        Some(_) => MSE_KEY_LENGTH,
                        None => HANDSHAKE_LENGTH,
                    };

                    let remaining = target_len.saturating_sub(pending.recv_buffer.len());
                    if remaining > 0 {
                        let mut buf = [0u8; MSE_KEY_LENGTH];
                        let read_len = remaining.min(MSE_KEY_LENGTH);
                        match pending.stream.read(&mut buf[..read_len]) {
                            Ok(0) => {
                                failed.push(id);
                                continue;
                            }
                            Ok(n) => {
                                pending.recv_buffer.extend_from_slice(&buf[..n]);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => {
                                failed.push(id);
                                continue;
                            }
                        }
                    }

                    if pending.recv_buffer.len() >= target_len {
                        if pending.recv_buffer.first().copied() == Some(PROTOCOL_STRING_LENGTH) && !pending.force_mse {
                            if pending.recv_buffer.len() >= HANDSHAKE_LENGTH
                                && &pending.recv_buffer[1..20] == PROTOCOL_STRING
                            {
                                match Self::validate_and_respond_plain(registry, pending) {
                                    Ok((info_hash, their_peer_id)) => {
                                        completed.push((id, info_hash, their_peer_id, None));
                                    }
                                    Err(_) => failed.push(id),
                                }
                                continue;
                            }
                            pending.force_mse = true;
                        }

                        if pending.recv_buffer.len() >= MSE_KEY_LENGTH {
                            let peer_pubkey = pending.recv_buffer.drain(..MSE_KEY_LENGTH).collect();
                            let base = MseHandshake::new_responder();
                            if pending.stream.write_all(base.get_public_key()).is_err() {
                                failed.push(id);
                                continue;
                            }
                            pending.mse_state = Some(MseState::AwaitingVc { base, peer_pubkey });
                        }
                    }
                }

                if pending.mse_state.is_some() {
                    match Self::process_mse_handshake(registry, pending) {
                        Ok(Some((info_hash, their_peer_id, mse_handshake))) => {
                            completed.push((id, info_hash, their_peer_id, Some(mse_handshake)));
                        }
                        Ok(None) => {}
                        Err(_) => failed.push(id),
                    }
                }
            }

            for id in failed {
                self.pending.remove(&id);
            }

            for (id, info_hash, their_peer_id, mse_handshake) in completed {
                if let Some(pending) = self.pending.remove(&id) {
                    accepted.push(AcceptedPeer {
                        stream: pending.stream,
                        addr: pending.addr,
                        info_hash,
                        their_peer_id,
                        mse_handshake,
                    });
                }
            }

            Ok(())
        }

        fn validate_and_respond_plain(
            registry: &HashMap<[u8; 20], InfoHashEntry>,
            pending: &mut PendingHandshake,
        ) -> Result<([u8; 20], [u8; 20])> {
            let data = &pending.recv_buffer;
            if data[0] != PROTOCOL_STRING_LENGTH {
                return Err(anyhow!("invalid protocol string length"));
            }

            if &data[1..20] != PROTOCOL_STRING {
                return Err(anyhow!("invalid protocol string"));
            }

            let their_info_hash: [u8; 20] = data[28..48]
                .try_into()
                .map_err(|_| anyhow!("invalid info hash length"))?;
            let their_peer_id: [u8; 20] = data[48..68]
                .try_into()
                .map_err(|_| anyhow!("invalid peer id length"))?;

            let entry = registry
                .get(&their_info_hash)
                .ok_or_else(|| anyhow!("unknown infohash"))?;

            let mut response = Vec::with_capacity(HANDSHAKE_LENGTH);
            response.push(PROTOCOL_STRING_LENGTH);
            response.extend_from_slice(PROTOCOL_STRING);
            let mut reserved = [0u8; 8];
            reserved[5] |= 0x10;
            response.extend_from_slice(&reserved);
            response.extend_from_slice(&their_info_hash);
            response.extend_from_slice(&entry.peer_id);

            pending.stream.write_all(&response)?;

            Ok((their_info_hash, their_peer_id))
        }

        fn process_mse_handshake(
            registry: &HashMap<[u8; 20], InfoHashEntry>,
            pending: &mut PendingHandshake,
        ) -> Result<Option<([u8; 20], [u8; 20], MseHandshake)>> {
            match pending.mse_state.take() {
                Some(MseState::AwaitingVc { base, peer_pubkey }) => {
                    if pending.recv_buffer.len() < MSE_VC_LENGTH {
                        let remaining = MSE_VC_LENGTH - pending.recv_buffer.len();
                        let mut buf = [0u8; MSE_VC_LENGTH];
                        match pending.stream.read(&mut buf[..remaining]) {
                            Ok(0) => return Err(anyhow!("connection closed")),
                            Ok(n) => pending.recv_buffer.extend_from_slice(&buf[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                pending.mse_state = Some(MseState::AwaitingVc { base, peer_pubkey });
                                return Ok(None);
                            }
                            Err(_) => return Err(anyhow!("recv failed")),
                        }
                    }

                    if pending.recv_buffer.len() < MSE_VC_LENGTH {
                        pending.mse_state = Some(MseState::AwaitingVc { base, peer_pubkey });
                        return Ok(None);
                    }

                    let encrypted_vc: Vec<u8> = pending.recv_buffer.drain(..MSE_VC_LENGTH).collect();

                    let Some((info_hash, our_peer_id, mut mse)) =
                        Self::select_mse_handshake(registry, &base, &peer_pubkey, &encrypted_vc)
                    else {
                        return Err(anyhow!("unable to resolve MSE infohash"));
                    };

                    let mut vc = [0u8; MSE_VC_LENGTH];
                    mse.encrypt(&mut vc);
                    pending.stream.write_all(&vc)?;

                    mse.set_stage(MseStage::Established);
                    pending.mse_state = Some(MseState::AwaitingHandshake { mse, info_hash, our_peer_id });
                    Ok(None)
                }
                Some(MseState::AwaitingHandshake { mut mse, info_hash, our_peer_id }) => {
                    if pending.recv_buffer.len() < HANDSHAKE_LENGTH {
                        let remaining = HANDSHAKE_LENGTH - pending.recv_buffer.len();
                        let mut buf = [0u8; HANDSHAKE_LENGTH];
                        match pending.stream.read(&mut buf[..remaining]) {
                            Ok(0) => return Err(anyhow!("connection closed")),
                            Ok(n) => pending.recv_buffer.extend_from_slice(&buf[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                pending.mse_state = Some(MseState::AwaitingHandshake { mse, info_hash, our_peer_id });
                                return Ok(None);
                            }
                            Err(_) => return Err(anyhow!("recv failed")),
                        }
                    }

                    if pending.recv_buffer.len() < HANDSHAKE_LENGTH {
                        pending.mse_state = Some(MseState::AwaitingHandshake { mse, info_hash, our_peer_id });
                        return Ok(None);
                    }

                    let mut handshake: Vec<u8> = pending.recv_buffer.drain(..HANDSHAKE_LENGTH).collect();
                    mse.decrypt(&mut handshake);

                    if handshake[0] != PROTOCOL_STRING_LENGTH {
                        return Err(anyhow!("invalid protocol string length"));
                    }

                    if &handshake[1..20] != PROTOCOL_STRING {
                        return Err(anyhow!("invalid protocol string"));
                    }

                    let their_info_hash: [u8; 20] = handshake[28..48]
                        .try_into()
                        .map_err(|_| anyhow!("invalid info hash length"))?;
                    let their_peer_id: [u8; 20] = handshake[48..68]
                        .try_into()
                        .map_err(|_| anyhow!("invalid peer id length"))?;

                    if their_info_hash != info_hash {
                        return Err(anyhow!("info hash mismatch"));
                    }

                    let mut response = Vec::with_capacity(HANDSHAKE_LENGTH);
                    response.push(PROTOCOL_STRING_LENGTH);
                    response.extend_from_slice(PROTOCOL_STRING);

                    let mut reserved = [0u8; 8];
                    reserved[5] |= 0x10;
                    response.extend_from_slice(&reserved);

                    response.extend_from_slice(&info_hash);
                    response.extend_from_slice(&our_peer_id);

                    mse.encrypt(&mut response);
                    pending.stream.write_all(&response)?;

                    Ok(Some((info_hash, their_peer_id, mse)))
                }
                None => Ok(None),
            }
        }

        fn select_mse_handshake(
            registry: &HashMap<[u8; 20], InfoHashEntry>,
            base: &MseHandshake,
            peer_pubkey: &[u8],
            encrypted_vc: &[u8],
        ) -> Option<([u8; 20], [u8; 20], MseHandshake)> {
            let mut attempts = 0;
            for (info_hash, entry) in registry.iter() {
                if attempts >= MAX_MSE_INFOHASH_ATTEMPTS {
                    break;
                }
                attempts += 1;

                let mut candidate = base.clone_without_ciphers();
                if candidate.compute_shared_secret(peer_pubkey, info_hash).is_err() {
                    continue;
                }
                let mut vc = encrypted_vc.to_vec();
                candidate.decrypt(&mut vc);
                if vc == [0u8; MSE_VC_LENGTH] {
                    return Some((*info_hash, entry.peer_id, candidate));
                }
            }
            None
        }

        fn cleanup_timed_out(&mut self) {
            let timed_out: Vec<usize> = self
                .pending
                .iter()
                .filter(|(_, p)| p.started_at.elapsed() > HANDSHAKE_TIMEOUT)
                .map(|(&id, _)| id)
                .collect();

            for id in timed_out {
                self.pending.remove(&id);
            }
        }

        pub fn close(&mut self) {
            self.pending.clear();
        }
    }

    fn accept_stream(listener: &TcpListener) -> Result<Option<(TcpStream, SocketAddr)>> {
        match listener.accept() {
            Ok((stream, addr)) => {
                stream.set_nonblocking(true)?;
                Ok(Some((stream, addr)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(anyhow!("accept failed: {}", e)),
        }
    }

    fn bind_v6_listener(port: u16) -> Result<TcpListener> {
        use libc::{bind, close, listen, setsockopt, sockaddr_in6, socket, AF_INET6, IPV6_V6ONLY};

        unsafe {
            let fd = socket(AF_INET6, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(anyhow!("socket(AF_INET6) failed"));
            }

            let v6_only: i32 = 1;
            let set_result = setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_V6ONLY,
                &v6_only as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if set_result != 0 {
                close(fd);
                return Err(anyhow!("setsockopt(IPV6_V6ONLY) failed"));
            }

            let addr = sockaddr_in6 {
                sin6_family: AF_INET6 as libc::sa_family_t,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
            };

            let bind_result = bind(
                fd,
                &addr as *const sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_in6>() as libc::socklen_t,
            );
            if bind_result != 0 {
                close(fd);
                return Err(anyhow!("bind(AF_INET6) failed"));
            }

            if listen(fd, 16) != 0 {
                close(fd);
                return Err(anyhow!("listen(AF_INET6) failed"));
            }

            Ok(TcpListener::from_raw_fd(fd))
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::{AcceptedPeer, PeerListener};

#[cfg(not(target_os = "windows"))]
pub use unix_impl::{AcceptedPeer, PeerListener};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
    use std::thread;

    #[test]
    fn test_listener_creation() {
        let listener = PeerListener::new(0);
        assert!(listener.is_ok());
    }

    #[test]
    fn test_listener_register_infohash() {
        let mut listener = PeerListener::new(0).unwrap();
        let info_hash = [1u8; 20];
        let peer_id = [2u8; 20];
        listener.register_infohash(info_hash, peer_id, 100);
    }

    #[test]
    fn test_accept_ipv6_peer() {
        let mut listener = PeerListener::new(0).unwrap();
        let info_hash = [3u8; 20];
        let peer_id = [4u8; 20];
        listener.register_infohash(info_hash, peer_id, 1);

        let port = listener.port();
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
        let mut stream = TcpStream::connect(addr).unwrap();

        let mut handshake = Vec::with_capacity(68);
        handshake.push(19);
        handshake.extend_from_slice(b"BitTorrent protocol");
        handshake.extend_from_slice(&[0u8; 8]);
        handshake.extend_from_slice(&info_hash);
        handshake.extend_from_slice(&peer_id);
        stream.write_all(&handshake).unwrap();

        let start = Instant::now();
        let mut accepted_v6 = None;
        while start.elapsed() < Duration::from_secs(1) {
            if let Ok(accepted) = listener.poll() {
                accepted_v6 = accepted.into_iter().find(|peer| matches!(peer.addr, SocketAddr::V6(_)));
                if accepted_v6.is_some() {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(accepted_v6.is_some());
    }
}
