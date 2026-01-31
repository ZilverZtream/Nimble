use anyhow::Result;
use std::net::SocketAddrV4;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{
        self, INVALID_SOCKET, SOCKET, SOCKET_ERROR, WSADATA, AF_INET, SOCK_STREAM,
        IPPROTO_TCP, FIONBIO, SOCKADDR_IN, SD_BOTH, WSAEWOULDBLOCK, WSAEINPROGRESS,
        WSAECONNRESET, FD_SET, TIMEVAL,
        SOL_SOCKET, SO_ERROR, SO_RCVTIMEO, SO_SNDTIMEO, SO_KEEPALIVE,
    };

    const MAX_RECV_BUFFER: usize = 65536;
    const CONNECT_TIMEOUT_MS: u32 = 10000;
    const RECV_TIMEOUT_MS: u32 = 30000;
    const SEND_TIMEOUT_MS: u32 = 30000;

    pub struct TcpSocket {
        socket: SOCKET,
        connected: bool,
        peer_addr: Option<SocketAddrV4>,
    }

    impl TcpSocket {
        pub fn new() -> Result<Self> {
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

        pub fn connect(&mut self, addr: SocketAddrV4) -> Result<()> {
            self.set_nonblocking(true)?;

            let sockaddr = sockaddr_from_v4(addr);
            let result = unsafe {
                WinSock::connect(
                    self.socket,
                    &sockaddr as *const SOCKADDR_IN as *const WinSock::SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
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

            self.connected = true;
            self.peer_addr = Some(addr);
            Ok(())
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

        pub fn peer_addr(&self) -> Option<SocketAddrV4> {
            self.peer_addr
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
}

#[cfg(not(target_os = "windows"))]
mod unix_impl {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    pub struct TcpSocket {
        stream: Option<TcpStream>,
        peer_addr: Option<SocketAddrV4>,
    }

    impl TcpSocket {
        pub fn new() -> Result<Self> {
            Ok(TcpSocket {
                stream: None,
                peer_addr: None,
            })
        }

        pub fn connect(&mut self, addr: SocketAddrV4) -> Result<()> {
            let stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            stream.set_nodelay(true)?;
            self.peer_addr = Some(addr);
            self.stream = Some(stream);
            Ok(())
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

        pub fn peer_addr(&self) -> Option<SocketAddrV4> {
            self.peer_addr
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
}

#[cfg(target_os = "windows")]
pub use windows_impl::TcpSocket;

#[cfg(not(target_os = "windows"))]
pub use unix_impl::TcpSocket;

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
