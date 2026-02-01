use anyhow::{Context, Result};
use std::net::{UdpSocket, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

const NAT_PMP_PORT: u16 = 5351;
const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_RETRIES: usize = 9;
const MAPPING_LIFETIME: u32 = 3600;
const RENEWAL_INTERVAL: Duration = Duration::from_secs(1800);

const PROTOCOL_TCP: u8 = 2;
const PROTOCOL_UDP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn to_nat_pmp(&self) -> u8 {
        match self {
            Protocol::Tcp => PROTOCOL_TCP,
            Protocol::Udp => PROTOCOL_UDP,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NatPmpMapping {
    pub external_port: u16,
    pub internal_port: u16,
    pub protocol: Protocol,
    pub lifetime: u32,
    pub created_at: Instant,
}

pub struct NatPmpClient {
    gateway: Option<Ipv4Addr>,
    socket: Option<UdpSocket>,
    external_addr: Option<Ipv4Addr>,
    mappings: Vec<NatPmpMapping>,
    last_renewal: Instant,
}

impl NatPmpClient {
    pub fn new() -> Self {
        NatPmpClient {
            gateway: None,
            socket: None,
            external_addr: None,
            mappings: Vec::new(),
            last_renewal: Instant::now(),
        }
    }

    pub fn discover(&mut self) -> Result<bool> {
        let gateway = Self::find_default_gateway()?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind UDP socket")?;

        socket
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .context("Failed to set socket timeout")?;

        socket
            .connect(SocketAddrV4::new(gateway, NAT_PMP_PORT))
            .context("Failed to connect to gateway")?;

        self.gateway = Some(gateway);
        self.socket = Some(socket);

        self.query_external_address()?;

        Ok(true)
    }

    fn find_default_gateway() -> Result<Ipv4Addr> {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            let output = Command::new("route")
                .args(&["print", "0.0.0.0"])
                .output()
                .context("Failed to run route command")?;

            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
                    if let Ok(addr) = parts[2].parse::<Ipv4Addr>() {
                        return Ok(addr);
                    }
                }
            }

            anyhow::bail!("Could not find default gateway")
        }

        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("Gateway discovery only supported on Windows")
        }
    }

    fn query_external_address(&mut self) -> Result<()> {
        let request = [0u8, 0];

        let socket = self.socket.as_ref()
            .context("No socket available")?;

        socket.send(&request)
            .context("Failed to send external address request")?;

        let mut response = [0u8; 12];
        let mut timeout = REQUEST_TIMEOUT;

        for retry in 0..MAX_RETRIES {
            match socket.recv(&mut response) {
                Ok(n) if n >= 12 => {
                    if response[0] == 0 && response[1] == 128 {
                        let addr = Ipv4Addr::new(
                            response[8],
                            response[9],
                            response[10],
                            response[11],
                        );
                        self.external_addr = Some(addr);
                        return Ok(());
                    }
                }
                Ok(_) => anyhow::bail!("Invalid response size"),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    if retry < MAX_RETRIES - 1 {
                        timeout *= 2;
                        socket.set_read_timeout(Some(timeout))?;
                        socket.send(&request)?;
                        continue;
                    }
                    anyhow::bail!("Timeout querying external address")
                }
                Err(e) => return Err(e.into()),
            }
        }

        anyhow::bail!("Failed to query external address")
    }

    pub fn add_port_mapping(
        &mut self,
        internal_port: u16,
        external_port: u16,
        protocol: Protocol,
        lifetime: Option<u32>,
    ) -> Result<u16> {
        let socket = self.socket.as_ref()
            .context("No socket available (discovery not complete)")?;

        let lifetime = lifetime.unwrap_or(MAPPING_LIFETIME);

        let mut request = [0u8; 12];
        request[0] = 0;
        request[1] = protocol.to_nat_pmp();
        request[2..4].copy_from_slice(&0u16.to_be_bytes());
        request[4..6].copy_from_slice(&internal_port.to_be_bytes());
        request[6..8].copy_from_slice(&external_port.to_be_bytes());
        request[8..12].copy_from_slice(&lifetime.to_be_bytes());

        socket.send(&request)
            .context("Failed to send port mapping request")?;

        let mut response = [0u8; 16];
        let mut timeout = REQUEST_TIMEOUT;

        for retry in 0..MAX_RETRIES {
            match socket.recv(&mut response) {
                Ok(n) if n >= 16 => {
                    if response[0] == 0 && response[1] == (128 + protocol.to_nat_pmp()) {
                        let result_code = u16::from_be_bytes([response[2], response[3]]);

                        if result_code != 0 {
                            anyhow::bail!("NAT-PMP error code: {}", result_code);
                        }

                        let mapped_external_port = u16::from_be_bytes([response[10], response[11]]);
                        let mapped_lifetime = u32::from_be_bytes([
                            response[12], response[13], response[14], response[15],
                        ]);

                        self.mappings.push(NatPmpMapping {
                            external_port: mapped_external_port,
                            internal_port,
                            protocol,
                            lifetime: mapped_lifetime,
                            created_at: Instant::now(),
                        });

                        return Ok(mapped_external_port);
                    }
                }
                Ok(_) => anyhow::bail!("Invalid response size"),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    if retry < MAX_RETRIES - 1 {
                        timeout *= 2;
                        socket.set_read_timeout(Some(timeout))?;
                        socket.send(&request)?;
                        continue;
                    }
                    anyhow::bail!("Timeout creating port mapping")
                }
                Err(e) => return Err(e.into()),
            }
        }

        anyhow::bail!("Failed to create port mapping")
    }

    pub fn delete_port_mapping(&mut self, internal_port: u16, protocol: Protocol) -> Result<()> {
        self.add_port_mapping(internal_port, 0, protocol, Some(0))?;

        self.mappings.retain(|m| !(m.internal_port == internal_port && m.protocol == protocol));

        Ok(())
    }

    pub fn renew_mappings(&mut self) -> Result<()> {
        if self.last_renewal.elapsed() < RENEWAL_INTERVAL {
            return Ok(());
        }

        let mappings_to_renew: Vec<_> = self.mappings.clone();

        for mapping in mappings_to_renew {
            let _ = self.add_port_mapping(
                mapping.internal_port,
                mapping.external_port,
                mapping.protocol,
                Some(mapping.lifetime),
            );
        }

        self.last_renewal = Instant::now();
        Ok(())
    }

    pub fn delete_all_mappings(&mut self) -> Result<()> {
        let mappings: Vec<_> = self.mappings.iter()
            .map(|m| (m.internal_port, m.protocol))
            .collect();

        for (port, protocol) in mappings {
            let _ = self.delete_port_mapping(port, protocol);
        }

        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.gateway.is_some() && self.socket.is_some() && self.external_addr.is_some()
    }

    pub fn get_external_address(&self) -> Option<Ipv4Addr> {
        self.external_addr
    }

    pub fn get_gateway(&self) -> Option<Ipv4Addr> {
        self.gateway
    }

    pub fn get_mappings(&self) -> &[NatPmpMapping] {
        &self.mappings
    }
}

impl Default for NatPmpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NatPmpClient {
    fn drop(&mut self) {
        let _ = self.delete_all_mappings();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_conversion() {
        assert_eq!(Protocol::Tcp.to_nat_pmp(), 2);
        assert_eq!(Protocol::Udp.to_nat_pmp(), 1);
    }

    #[test]
    fn test_client_creation() {
        let client = NatPmpClient::new();
        assert!(!client.is_available());
        assert_eq!(client.get_mappings().len(), 0);
        assert!(client.get_external_address().is_none());
        assert!(client.get_gateway().is_none());
    }

    #[test]
    fn test_mapping_request_format() {
        let mut request = [0u8; 12];
        request[0] = 0;
        request[1] = Protocol::Tcp.to_nat_pmp();
        request[4..6].copy_from_slice(&6881u16.to_be_bytes());
        request[6..8].copy_from_slice(&6881u16.to_be_bytes());
        request[8..12].copy_from_slice(&3600u32.to_be_bytes());

        assert_eq!(request[0], 0);
        assert_eq!(request[1], 2);
        assert_eq!(u16::from_be_bytes([request[4], request[5]]), 6881);
        assert_eq!(u16::from_be_bytes([request[6], request[7]]), 6881);
        assert_eq!(u32::from_be_bytes([request[8], request[9], request[10], request[11]]), 3600);
    }
}
