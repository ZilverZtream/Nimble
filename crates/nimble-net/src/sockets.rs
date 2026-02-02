use anyhow::Result;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

/// Opaque raw socket handle type for readiness polling.
/// On Windows this is SOCKET (usize), on Unix this is RawFd (i32).
#[cfg(target_os = "windows")]
pub type RawSocket = usize;

#[cfg(not(target_os = "windows"))]
pub type RawSocket = i32;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{
        self, INVALID_SOCKET, SOCKET, SOCKET_ERROR, WSADATA, AF_INET, AF_INET6, SOCK_STREAM,
        IPPROTO_TCP, FIONBIO, SOCKADDR_IN, SOCKADDR_IN6, SD_BOTH, WSAEWOULDBLOCK, WSAEINPROGRESS,
        WSAECONNRESET, FD_SET, TIMEVAL,
        SOL_SOCKET, SO_ERROR, SO_RCVTIMEO, SO_SNDTIMEO, SO_KEEPALIVE, SO_RCVBUF, SO_SNDBUF, IPV6_V6ONLY,
    };

    const MAX_RECV_BUFFER: usize = 65536;
    const CONNECT_TIMEOUT_MS: u32 = 10000;
    const RECV_TIMEOUT_MS: u32 = 30000;
    const SEND_TIMEOUT_MS: u32 = 30000;

    /// Conservative TCP buffer sizes (Step 3: TCP Tuning)
    /// 512KB is sufficient to buffer 20ms of data at ~200Mbps per peer.
    /// Total Kernel Memory for 500 peers: ~250MB (Safe).
    pub const SO_RCVBUF_SIZE: i32 = 512 * 1024;
    pub const SO_SNDBUF_SIZE: i32 = 256 * 1024;
    /// For high-priority peers (fast uploaders), dynamically upgrade to 2MB
    pub const SO_RCVBUF_SIZE_PRIORITY: i32 = 2 * 1024 * 1024;

    /// Maximum sockets that can be polled in a single select() call (Windows FD_SETSIZE).
    const MAX_POLL_SOCKETS: usize = 64;

    pub struct TcpSocket {
        socket: SOCKET,
        connected: bool,
        peer_addr: Option<SocketAddr>,
    }

    impl TcpSocket {
        pub fn new() -> Result<Self> {
            Self::new_v4()
        }

        pub fn new_v4() -> Result<Self> {
            init_winsock()?;

            let socket = unsafe {
                WinSock::socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP)
            };

            if socket == INVALID_SOCKET {
                let err = get_last_error();
                anyhow::bail!("socket() failed: error {}", err);
            }

            Ok(TcpSocket {
                socket,
                connected: false,
                peer_addr: None,
            })
        }

        pub fn new_v6() -> Result<Self> {
            init_winsock()?;

            let socket = unsafe {
                WinSock::socket(AF_INET6 as i32, SOCK_STREAM, IPPROTO_TCP)
            };

            if socket == INVALID_SOCKET {
                let err = get_last_error();
                anyhow::bail!("socket() failed: error {}", err);
            }

            let v6only: i32 = 1;
            unsafe {
                WinSock::setsockopt(
                    socket,
                    windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
                    IPV6_V6ONLY as i32,
                    &v6only as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            Ok(TcpSocket {
                socket,
                connected: false,
                peer_addr: None,
            })
        }

        pub fn new_for_addr(addr: &SocketAddr) -> Result<Self> {
            match addr {
                SocketAddr::V4(_) => Self::new_v4(),
                SocketAddr::V6(_) => Self::new_v6(),
            }
        }

        /// # Safety and Ownership
        ///
        /// This function takes FULL OWNERSHIP of the provided SOCKET handle.
        /// The socket will be closed when this TcpSocket is dropped.
        ///
        /// **CRITICAL**: The caller MUST NOT retain any references to the socket
        /// or attempt to close it. After calling this function, the socket handle
        /// is INVALID from the caller's perspective.
        ///
        /// **Windows-specific hazard**: If the caller retains the SOCKET handle
        /// and it gets reused by the OS for a different connection before this
        /// TcpSocket is dropped, calling closesocket on the reused handle will
        /// close the wrong connection.
        ///
        /// **Correct usage**:
        /// ```no_run
        /// use windows_sys::Win32::Networking::WinSock::SOCKET;
        /// let raw_socket: SOCKET = /* accept() or similar */;
        /// let tcp_socket = TcpSocket::from_raw_socket(raw_socket, addr)?;
        /// // raw_socket is now INVALID - do not use it again
        /// ```
        pub fn from_raw_socket(socket: SOCKET, peer_addr: SocketAddr) -> Result<Self> {
            if socket == INVALID_SOCKET {
                anyhow::bail!("invalid socket");
            }

            let sock = TcpSocket {
                socket,
                connected: true,
                peer_addr: Some(peer_addr),
            };

            sock.set_nonblocking(true)?;
            sock.set_timeouts(RECV_TIMEOUT_MS, SEND_TIMEOUT_MS)?;
            sock.set_keepalive(true)?;
            // Apply TCP buffer tuning for optimal throughput (RFC-101 Step 3)
            let _ = sock.apply_default_tuning();

            Ok(sock)
        }

        /// Consumes the TcpSocket and returns the raw SOCKET handle WITHOUT closing it.
        ///
        /// # Safety
        ///
        /// After calling this function, the caller is responsible for closing
        /// the socket. Failure to do so will leak the socket handle.
        ///
        /// This is useful for transferring ownership to another abstraction
        /// without going through a close/reopen cycle.
        pub fn into_raw_socket(mut self) -> SOCKET {
            let socket = self.socket;
            self.socket = INVALID_SOCKET;
            std::mem::forget(self);
            socket
        }

        fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
            let mut mode: u32 = if nonblocking { 1 } else { 0 };
            let result = unsafe {
                WinSock::ioctlsocket(self.socket, FIONBIO as i32, &mut mode)
            };

            if result == SOCKET_ERROR {
                anyhow::bail!("ioctlsocket(FIONBIO) failed: {}", get_last_error());
            }
            Ok(())
        }

        fn set_timeouts(&self, recv_ms: u32, send_ms: u32) -> Result<()> {
            let recv_timeout = recv_ms as i32;
            let send_timeout = send_ms as i32;

            unsafe {
                let result = WinSock::setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &recv_timeout as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
                if result == SOCKET_ERROR {
                    anyhow::bail!("setsockopt(SO_RCVTIMEO) failed: {}", get_last_error());
                }

                let result = WinSock::setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_SNDTIMEO,
                    &send_timeout as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
                if result == SOCKET_ERROR {
                    anyhow::bail!("setsockopt(SO_SNDTIMEO) failed: {}", get_last_error());
                }
            }
            Ok(())
        }

        fn set_keepalive(&self, enable: bool) -> Result<()> {
            let value: i32 = if enable { 1 } else { 0 };
            let result = unsafe {
                WinSock::setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_KEEPALIVE,
                    &value as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                )
            };
            if result == SOCKET_ERROR {
                anyhow::bail!("setsockopt(SO_KEEPALIVE) failed: {}", get_last_error());
            }
            Ok(())
        }

        pub fn connect(&mut self, addr: SocketAddr) -> Result<()> {
            self.set_nonblocking(true)?;

            let result = match addr {
                SocketAddr::V4(v4_addr) => {
                    let sockaddr = sockaddr_from_v4(v4_addr);
                    unsafe {
                        WinSock::connect(
                            self.socket,
                            &sockaddr as *const SOCKADDR_IN as *const WinSock::SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN>() as i32,
                        )
                    }
                }
                SocketAddr::V6(v6_addr) => {
                    let sockaddr = sockaddr_from_v6(v6_addr);
                    unsafe {
                        WinSock::connect(
                            self.socket,
                            &sockaddr as *const SOCKADDR_IN6 as *const WinSock::SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN6>() as i32,
                        )
                    }
                }
            };

            if result == SOCKET_ERROR {
                let err = get_last_error();
                if err != WSAEWOULDBLOCK as i32 && err != WSAEINPROGRESS as i32 {
                    anyhow::bail!("connect() failed immediately: error {}", err);
                }
            }

            if !self.wait_for_connect(CONNECT_TIMEOUT_MS)? {
                anyhow::bail!("connect() timed out");
            }

            self.set_nonblocking(false)?;
            self.set_timeouts(RECV_TIMEOUT_MS, SEND_TIMEOUT_MS)?;
            self.set_keepalive(true)?;
            // Apply TCP buffer tuning for optimal throughput (RFC-101 Step 3)
            let _ = self.apply_default_tuning();

            self.connected = true;
            self.peer_addr = Some(addr);
            Ok(())
        }

        pub fn connect_v4(&mut self, addr: SocketAddrV4) -> Result<()> {
            self.connect(SocketAddr::V4(addr))
        }

        fn wait_for_connect(&self, timeout_ms: u32) -> Result<bool> {
            let mut write_set = FD_SET {
                fd_count: 1,
                fd_array: [0; 64],
            };
            write_set.fd_array[0] = self.socket;

            let mut except_set = FD_SET {
                fd_count: 1,
                fd_array: [0; 64],
            };
            except_set.fd_array[0] = self.socket;

            let timeout = TIMEVAL {
                tv_sec: (timeout_ms / 1000) as i32,
                tv_usec: ((timeout_ms % 1000) * 1000) as i32,
            };

            let result = unsafe {
                WinSock::select(
                    0,
                    std::ptr::null_mut(),
                    &mut write_set,
                    &mut except_set,
                    &timeout,
                )
            };

            if result == SOCKET_ERROR {
                anyhow::bail!("select() failed: {}", get_last_error());
            }

            if result == 0 {
                return Ok(false);
            }

            if except_set.fd_count > 0 {
                let mut error: i32 = 0;
                let mut error_len: i32 = std::mem::size_of::<i32>() as i32;
                unsafe {
                    WinSock::getsockopt(
                        self.socket,
                        SOL_SOCKET,
                        SO_ERROR,
                        &mut error as *mut i32 as *mut u8,
                        &mut error_len,
                    );
                }
                anyhow::bail!("connect() failed: socket error {}", error);
            }

            Ok(write_set.fd_count > 0)
        }

        pub fn send(&self, data: &[u8]) -> Result<usize> {
            if !self.connected {
                anyhow::bail!("socket not connected");
            }

            let result = unsafe {
                WinSock::send(
                    self.socket,
                    data.as_ptr(),
                    data.len() as i32,
                    0,
                )
            };

            if result == SOCKET_ERROR {
                let err = get_last_error();
                anyhow::bail!("send() failed: error {}", err);
            }

            Ok(result as usize)
        }

        pub fn send_all(&self, data: &[u8]) -> Result<()> {
            let mut sent = 0;
            while sent < data.len() {
                let n = self.send(&data[sent..])?;
                if n == 0 {
                    anyhow::bail!("send() returned 0");
                }
                sent += n;
            }
            Ok(())
        }

        pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
            if !self.connected {
                anyhow::bail!("socket not connected");
            }

            let result = unsafe {
                WinSock::recv(
                    self.socket,
                    buf.as_mut_ptr(),
                    buf.len().min(MAX_RECV_BUFFER) as i32,
                    0,
                )
            };

            if result == SOCKET_ERROR {
                let err = get_last_error();
                if err == WSAECONNRESET as i32 {
                    return Ok(0);
                }
                anyhow::bail!("recv() failed: error {}", err);
            }

            Ok(result as usize)
        }

        pub fn recv_exact(&self, buf: &mut [u8]) -> Result<()> {
            let mut received = 0;
            while received < buf.len() {
                let n = self.recv(&mut buf[received..])?;
                if n == 0 {
                    anyhow::bail!("connection closed");
                }
                received += n;
            }
            Ok(())
        }

        pub fn is_connected(&self) -> bool {
            self.connected
        }

        pub fn peer_addr(&self) -> Option<SocketAddr> {
            self.peer_addr
        }

        pub fn peer_addr_v4(&self) -> Option<SocketAddrV4> {
            match self.peer_addr {
                Some(SocketAddr::V4(addr)) => Some(addr),
                _ => None,
            }
        }

        /// Returns the raw socket handle for use with poll_readable_sockets().
        /// The socket remains owned by this TcpSocket.
        pub fn raw_socket(&self) -> super::RawSocket {
            self.socket as super::RawSocket
        }

        /// Sets the TCP buffer sizes for this socket (RFC-101 Step 3).
        /// Uses conservative defaults that balance throughput with memory usage.
        pub fn set_buffer_sizes(&self, recv_size: i32, send_size: i32) -> Result<()> {
            let _ = set_socket_buffer_sizes(self.socket, recv_size, send_size)?;
            Ok(())
        }

        /// Applies default TCP buffer tuning for peer connections.
        pub fn apply_default_tuning(&self) -> Result<()> {
            self.set_buffer_sizes(SO_RCVBUF_SIZE, SO_SNDBUF_SIZE)
        }

        /// Applies priority TCP buffer tuning for fast peers.
        pub fn apply_priority_tuning(&self) -> Result<()> {
            self.set_buffer_sizes(SO_RCVBUF_SIZE_PRIORITY, SO_SNDBUF_SIZE)
        }

        pub fn close(&mut self) {
            if self.socket != INVALID_SOCKET {
                unsafe {
                    WinSock::shutdown(self.socket, SD_BOTH);
                    WinSock::closesocket(self.socket);
                }
                self.socket = INVALID_SOCKET;
                self.connected = false;
                self.peer_addr = None;
            }
        }
    }

    impl Drop for TcpSocket {
        fn drop(&mut self) {
            self.close();
        }
    }

    fn sockaddr_from_v4(addr: SocketAddrV4) -> SOCKADDR_IN {
        let ip_bytes = addr.ip().octets();
        SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: addr.port().to_be(),
            sin_addr: WinSock::IN_ADDR {
                S_un: WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip_bytes),
                },
            },
            sin_zero: [0; 8],
        }
    }

    fn sockaddr_from_v6(addr: SocketAddrV6) -> SOCKADDR_IN6 {
        let ip_bytes = addr.ip().octets();
        SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: addr.port().to_be(),
            sin6_flowinfo: addr.flowinfo(),
            sin6_addr: WinSock::IN6_ADDR {
                u: WinSock::IN6_ADDR_0 {
                    Byte: ip_bytes,
                },
            },
            sin6_scope_id: addr.scope_id(),
        }
    }

    fn get_last_error() -> i32 {
        unsafe { WinSock::WSAGetLastError() }
    }

    static WINSOCK_INIT: std::sync::Once = std::sync::Once::new();

    fn init_winsock() -> Result<()> {
        static mut INIT_RESULT: Option<i32> = None;

        WINSOCK_INIT.call_once(|| {
            let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
            let result = unsafe {
                WinSock::WSAStartup(0x0202, &mut wsa_data)
            };
            unsafe { INIT_RESULT = Some(result); }
        });

        unsafe {
            if let Some(result) = INIT_RESULT {
                if result != 0 {
                    anyhow::bail!("WSAStartup failed: {}", result);
                }
            }
        }
        Ok(())
    }

    /// Polls multiple sockets for read readiness using select().
    /// Returns the indices of sockets that are ready to read.
    ///
    /// This reduces syscall overhead from O(N) recv() calls per tick to a single
    /// select() call, addressing the "polling storm" bottleneck (RFC-101 Step 1).
    ///
    /// # Arguments
    /// * `sockets` - Slice of raw socket handles to poll
    /// * `timeout_ms` - Timeout in milliseconds (0 = immediate return)
    ///
    /// # Returns
    /// Vector of indices into the input slice that are ready to read
    pub fn poll_readable_sockets(sockets: &[super::RawSocket], timeout_ms: u32) -> Result<Vec<usize>> {
        if sockets.is_empty() {
            return Ok(Vec::new());
        }

        init_winsock()?;

        let mut ready_indices = Vec::new();

        // Process sockets in batches of MAX_POLL_SOCKETS (FD_SETSIZE limit)
        for batch_start in (0..sockets.len()).step_by(MAX_POLL_SOCKETS) {
            let batch_end = (batch_start + MAX_POLL_SOCKETS).min(sockets.len());
            let batch = &sockets[batch_start..batch_end];

            let mut read_set = FD_SET {
                fd_count: batch.len() as u32,
                fd_array: [0; 64],
            };

            for (i, &socket) in batch.iter().enumerate() {
                read_set.fd_array[i] = socket as SOCKET;
            }

            // Use short timeout for first batch, zero for subsequent batches
            let batch_timeout = if batch_start == 0 { timeout_ms } else { 0 };
            let timeout = TIMEVAL {
                tv_sec: (batch_timeout / 1000) as i32,
                tv_usec: ((batch_timeout % 1000) * 1000) as i32,
            };

            let result = unsafe {
                WinSock::select(
                    0, // Ignored on Windows
                    &mut read_set,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &timeout,
                )
            };

            if result == SOCKET_ERROR {
                let err = get_last_error();
                // WSAENOTSOCK (10038) means socket is invalid, skip it
                if err == 10038 {
                    continue;
                }
                anyhow::bail!("select() failed: error {}", err);
            }

            if result > 0 {
                // Check which sockets in this batch are ready
                for (i, &socket) in batch.iter().enumerate() {
                    let is_set = unsafe {
                        // Manually check if socket is in the set
                        let mut found = false;
                        for j in 0..read_set.fd_count as usize {
                            if read_set.fd_array[j] == socket as SOCKET {
                                found = true;
                                break;
                            }
                        }
                        found
                    };
                    if is_set {
                        ready_indices.push(batch_start + i);
                    }
                }
            }
        }

        Ok(ready_indices)
    }

    /// Sets the receive and send buffer sizes on a socket.
    /// Returns the actual buffer sizes set by the OS.
    pub fn set_socket_buffer_sizes(socket: SOCKET, recv_size: i32, send_size: i32) -> Result<(i32, i32)> {
        let result = unsafe {
            WinSock::setsockopt(
                socket,
                SOL_SOCKET,
                SO_RCVBUF,
                &recv_size as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            anyhow::bail!("setsockopt(SO_RCVBUF) failed: {}", get_last_error());
        }

        let result = unsafe {
            WinSock::setsockopt(
                socket,
                SOL_SOCKET,
                SO_SNDBUF,
                &send_size as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            anyhow::bail!("setsockopt(SO_SNDBUF) failed: {}", get_last_error());
        }

        // Get actual sizes set
        let mut actual_recv: i32 = 0;
        let mut actual_send: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as i32;

        unsafe {
            WinSock::getsockopt(
                socket,
                SOL_SOCKET,
                SO_RCVBUF,
                &mut actual_recv as *mut i32 as *mut u8,
                &mut len,
            );
            WinSock::getsockopt(
                socket,
                SOL_SOCKET,
                SO_SNDBUF,
                &mut actual_send as *mut i32 as *mut u8,
                &mut len,
            );
        }

        Ok((actual_recv, actual_send))
    }
}

#[cfg(not(target_os = "windows"))]
mod unix_impl {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    /// Conservative TCP buffer sizes (Step 3: TCP Tuning)
    pub const SO_RCVBUF_SIZE: i32 = 512 * 1024;
    pub const SO_SNDBUF_SIZE: i32 = 256 * 1024;
    pub const SO_RCVBUF_SIZE_PRIORITY: i32 = 2 * 1024 * 1024;

    pub struct TcpSocket {
        stream: Option<TcpStream>,
        peer_addr: Option<SocketAddr>,
    }

    impl TcpSocket {
        pub fn new() -> Result<Self> {
            Ok(TcpSocket {
                stream: None,
                peer_addr: None,
            })
        }

        pub fn new_v4() -> Result<Self> {
            Self::new()
        }

        pub fn new_v6() -> Result<Self> {
            Self::new()
        }

        pub fn new_for_addr(_addr: &SocketAddr) -> Result<Self> {
            Self::new()
        }

        /// Takes ownership of the provided TcpStream.
        ///
        /// The stream will be closed when this TcpSocket is dropped.
        /// The caller must not retain any references to the stream.
        pub fn from_raw_socket(stream: TcpStream, peer_addr: SocketAddr) -> Result<Self> {
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            stream.set_nodelay(true)?;

            Ok(TcpSocket {
                stream: Some(stream),
                peer_addr: Some(peer_addr),
            })
        }

        /// Consumes the TcpSocket and returns the raw TcpStream WITHOUT closing it.
        ///
        /// After calling this function, the caller is responsible for closing
        /// the stream.
        pub fn into_raw_socket(mut self) -> Option<TcpStream> {
            self.stream.take()
        }

        pub fn connect(&mut self, addr: SocketAddr) -> Result<()> {
            let stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            stream.set_nodelay(true)?;
            self.peer_addr = Some(addr);
            self.stream = Some(stream);
            Ok(())
        }

        pub fn connect_v4(&mut self, addr: SocketAddrV4) -> Result<()> {
            self.connect(SocketAddr::V4(addr))
        }

        pub fn send(&mut self, data: &[u8]) -> Result<usize> {
            let stream = self.stream.as_mut()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?;
            Ok(stream.write(data)?)
        }

        pub fn send_all(&mut self, data: &[u8]) -> Result<()> {
            let stream = self.stream.as_mut()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?;
            stream.write_all(data)?;
            Ok(())
        }

        pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            let stream = self.stream.as_mut()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?;
            Ok(stream.read(buf)?)
        }

        pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<()> {
            let stream = self.stream.as_mut()
                .ok_or_else(|| anyhow::anyhow!("not connected"))?;
            stream.read_exact(buf)?;
            Ok(())
        }

        pub fn is_connected(&self) -> bool {
            self.stream.is_some()
        }

        pub fn peer_addr(&self) -> Option<SocketAddr> {
            self.peer_addr
        }

        pub fn peer_addr_v4(&self) -> Option<SocketAddrV4> {
            match self.peer_addr {
                Some(SocketAddr::V4(addr)) => Some(addr),
                _ => None,
            }
        }

        /// Returns the raw file descriptor for use with poll_readable_sockets().
        pub fn raw_socket(&self) -> super::RawSocket {
            self.stream.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1)
        }

        /// Sets TCP buffer sizes (no-op on Unix as we use system defaults).
        pub fn set_buffer_sizes(&self, _recv_size: i32, _send_size: i32) -> Result<()> {
            // On Unix, the buffer sizes are typically managed by the kernel
            // and set via sysctl. We keep the method for API compatibility.
            Ok(())
        }

        /// Applies default TCP buffer tuning (no-op on Unix).
        pub fn apply_default_tuning(&self) -> Result<()> {
            Ok(())
        }

        /// Applies priority TCP buffer tuning (no-op on Unix).
        pub fn apply_priority_tuning(&self) -> Result<()> {
            Ok(())
        }

        pub fn close(&mut self) {
            self.stream = None;
            self.peer_addr = None;
        }
    }

    impl Drop for TcpSocket {
        fn drop(&mut self) {
            self.close();
        }
    }

    /// Polls multiple sockets for read readiness using poll() on Unix.
    pub fn poll_readable_sockets(sockets: &[super::RawSocket], timeout_ms: u32) -> Result<Vec<usize>> {
        use libc::{poll, pollfd, POLLIN};

        if sockets.is_empty() {
            return Ok(Vec::new());
        }

        let mut pollfds: Vec<pollfd> = sockets
            .iter()
            .map(|&fd| pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            })
            .collect();

        let result = unsafe { poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms as i32) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is not fatal
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok(Vec::new());
            }
            anyhow::bail!("poll() failed: {}", err);
        }

        let mut ready_indices = Vec::new();
        for (i, pfd) in pollfds.iter().enumerate() {
            if pfd.revents & POLLIN != 0 {
                ready_indices.push(i);
            }
        }

        Ok(ready_indices)
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::TcpSocket;

#[cfg(target_os = "windows")]
pub use windows_impl::{poll_readable_sockets, SO_RCVBUF_SIZE, SO_SNDBUF_SIZE, SO_RCVBUF_SIZE_PRIORITY};

#[cfg(not(target_os = "windows"))]
pub use unix_impl::TcpSocket;

#[cfg(not(target_os = "windows"))]
pub use unix_impl::{poll_readable_sockets, SO_RCVBUF_SIZE, SO_SNDBUF_SIZE, SO_RCVBUF_SIZE_PRIORITY};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_creation() {
        let socket = TcpSocket::new();
        assert!(socket.is_ok());
    }

    #[test]
    fn test_socket_not_connected() {
        let socket = TcpSocket::new().unwrap();
        assert!(!socket.is_connected());
    }
}
