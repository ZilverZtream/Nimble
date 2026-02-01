use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket, Ipv4Addr};
use std::time::{Duration, Instant};

const SSDP_MULTICAST_ADDR: &str = "239.255.255.250:1900";
const SSDP_SEARCH_TARGET: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
const RENEWAL_INTERVAL: Duration = Duration::from_secs(1200);
const MAPPING_LEASE_DURATION: u32 = 3600;

const MSEARCH_REQUEST: &str = "M-SEARCH * HTTP/1.1\r
Host: 239.255.255.250:1900\r
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r
Man: \"ssdp:discover\"\r
MX: 3\r
\r
";

#[derive(Debug, Clone)]
pub struct UpnpMapping {
    pub external_port: u16,
    pub internal_port: u16,
    pub protocol: Protocol,
    pub description: String,
    pub created_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        }
    }
}

pub struct UpnpClient {
    control_url: Option<String>,
    service_type: Option<String>,
    local_addr: String,
    mappings: Vec<UpnpMapping>,
    last_renewal: Instant,
}

impl UpnpClient {
    pub fn new() -> Self {
        UpnpClient {
            control_url: None,
            service_type: None,
            local_addr: String::new(),
            mappings: Vec::new(),
            last_renewal: Instant::now(),
        }
    }

    pub fn discover(&mut self) -> Result<bool> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind UDP socket for SSDP")?;

        socket
            .set_read_timeout(Some(DISCOVERY_TIMEOUT))
            .context("Failed to set socket timeout")?;

        socket
            .send_to(MSEARCH_REQUEST.as_bytes(), SSDP_MULTICAST_ADDR)
            .context("Failed to send M-SEARCH request")?;

        let mut buf = vec![0u8; 2048];
        let mut location_url = None;

        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, _)) => {
                    let response = String::from_utf8_lossy(&buf[..n]);

                    if response.contains("InternetGatewayDevice") {
                        if let Some(url) = Self::extract_location(&response) {
                            location_url = Some(url.to_string());
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }

        if let Some(url) = location_url {
            self.fetch_device_description(&url)?;

            if let Ok(addr) = socket.local_addr() {
                if let SocketAddr::V4(v4) = addr {
                    self.local_addr = v4.ip().to_string();
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn extract_location(response: &str) -> Option<&str> {
        for line in response.lines() {
            let line = line.trim();
            if line.to_lowercase().starts_with("location:") {
                return Some(line[9..].trim());
            }
        }
        None
    }

    fn fetch_device_description(&mut self, url: &str) -> Result<()> {
        let xml = self.http_get(url)?;

        if let Some(control_url) = Self::parse_control_url(&xml) {
            let base_url = Self::get_base_url(url);
            let full_control_url = if control_url.starts_with("http") {
                control_url.to_string()
            } else if control_url.starts_with('/') {
                format!("{}{}", base_url, control_url)
            } else {
                format!("{}/{}", base_url, control_url)
            };

            self.control_url = Some(full_control_url);

            if xml.contains("WANIPConnection") {
                self.service_type = Some("urn:schemas-upnp-org:service:WANIPConnection:1".to_string());
            } else if xml.contains("WANPPPConnection") {
                self.service_type = Some("urn:schemas-upnp-org:service:WANPPPConnection:1".to_string());
            }
        }

        Ok(())
    }

    fn parse_control_url(xml: &str) -> Option<&str> {
        let mut in_wan_service = false;

        for line in xml.lines() {
            let line = line.trim();

            if line.contains("WANIPConnection") || line.contains("WANPPPConnection") {
                in_wan_service = true;
            }

            if in_wan_service && line.contains("<controlURL>") {
                if let Some(start) = line.find("<controlURL>") {
                    if let Some(end) = line.find("</controlURL>") {
                        let url = &line[start + 12..end];
                        return Some(url);
                    }
                }
            }
        }

        None
    }

    fn get_base_url(url: &str) -> String {
        if let Some(pos) = url.find("://") {
            if let Some(end) = url[pos + 3..].find('/') {
                return url[..pos + 3 + end].to_string();
            }
        }
        url.to_string()
    }

    fn http_get(&self, url: &str) -> Result<String> {
        let client = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build();

        let response = client
            .get(url)
            .call()
            .context("HTTP GET request failed")?;

        response
            .into_string()
            .context("Failed to read response body")
    }

    pub fn add_port_mapping(
        &mut self,
        external_port: u16,
        internal_port: u16,
        protocol: Protocol,
        description: &str,
    ) -> Result<()> {
        let control_url = self.control_url.as_ref()
            .context("No control URL available (discovery not complete)")?;

        let service_type = self.service_type.as_ref()
            .context("No service type available")?;

        let soap_body = format!(
            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="{}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{}</NewExternalPort>
<NewProtocol>{}</NewProtocol>
<NewInternalPort>{}</NewInternalPort>
<NewInternalClient>{}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{}</NewPortMappingDescription>
<NewLeaseDuration>{}</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"#,
            service_type,
            external_port,
            protocol.as_str(),
            internal_port,
            self.local_addr,
            description,
            MAPPING_LEASE_DURATION
        );

        self.soap_request(control_url, service_type, "AddPortMapping", &soap_body)?;

        self.mappings.push(UpnpMapping {
            external_port,
            internal_port,
            protocol,
            description: description.to_string(),
            created_at: Instant::now(),
        });

        Ok(())
    }

    pub fn delete_port_mapping(&mut self, external_port: u16, protocol: Protocol) -> Result<()> {
        let control_url = self.control_url.as_ref()
            .context("No control URL available")?;

        let service_type = self.service_type.as_ref()
            .context("No service type available")?;

        let soap_body = format!(
            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="{}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{}</NewExternalPort>
<NewProtocol>{}</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>"#,
            service_type, external_port, protocol.as_str()
        );

        self.soap_request(control_url, service_type, "DeletePortMapping", &soap_body)?;

        self.mappings.retain(|m| !(m.external_port == external_port && m.protocol == protocol));

        Ok(())
    }

    fn soap_request(
        &self,
        url: &str,
        service_type: &str,
        action: &str,
        body: &str,
    ) -> Result<String> {
        let client = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build();

        let soap_action = format!("\"{}#{}\"", service_type, action);

        let response = client
            .post(url)
            .set("Content-Type", "text/xml; charset=\"utf-8\"")
            .set("SOAPAction", &soap_action)
            .send_string(body)
            .context("SOAP request failed")?;

        response
            .into_string()
            .context("Failed to read SOAP response")
    }

    pub fn renew_mappings(&mut self) -> Result<()> {
        if self.last_renewal.elapsed() < RENEWAL_INTERVAL {
            return Ok(());
        }

        let mappings_to_renew: Vec<_> = self.mappings.clone();

        for mapping in mappings_to_renew {
            let _ = self.add_port_mapping(
                mapping.external_port,
                mapping.internal_port,
                mapping.protocol,
                &mapping.description,
            );
        }

        self.last_renewal = Instant::now();
        Ok(())
    }

    pub fn delete_all_mappings(&mut self) -> Result<()> {
        let mappings: Vec<_> = self.mappings.iter().map(|m| (m.external_port, m.protocol)).collect();

        for (port, protocol) in mappings {
            let _ = self.delete_port_mapping(port, protocol);
        }

        Ok(())
    }

    pub fn is_available(&self) -> bool {
        self.control_url.is_some() && self.service_type.is_some()
    }

    pub fn get_mappings(&self) -> &[UpnpMapping] {
        &self.mappings
    }
}

impl Default for UpnpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UpnpClient {
    fn drop(&mut self) {
        let _ = self.delete_all_mappings();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "TCP");
        assert_eq!(Protocol::Udp.as_str(), "UDP");
    }

    #[test]
    fn test_extract_location() {
        let response = "HTTP/1.1 200 OK\r\nLocation: http://192.168.1.1:5000/desc.xml\r\n";
        let location = UpnpClient::extract_location(response);
        assert_eq!(location, Some("http://192.168.1.1:5000/desc.xml"));
    }

    #[test]
    fn test_get_base_url() {
        let url = "http://192.168.1.1:5000/desc.xml";
        let base = UpnpClient::get_base_url(url);
        assert_eq!(base, "http://192.168.1.1:5000");
    }

    #[test]
    fn test_parse_control_url() {
        let xml = r#"
            <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/IPConn</controlURL>
            </service>
        "#;
        let control_url = UpnpClient::parse_control_url(xml);
        assert_eq!(control_url, Some("/ctl/IPConn"));
    }

    #[test]
    fn test_client_creation() {
        let client = UpnpClient::new();
        assert!(!client.is_available());
        assert_eq!(client.get_mappings().len(), 0);
    }
}
