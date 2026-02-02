use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) fn is_valid_peer_ip_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    if octets[0] == 0 {
        return false;
    }
    if octets[0] == 10 {
        return false;
    }
    if octets[0] == 127 {
        return false;
    }
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return false;
    }
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }
    if octets[0] >= 224 {
        return false;
    }
    if ip.is_broadcast() {
        return false;
    }

    true
}

pub(crate) fn is_valid_peer_ip_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if ip.is_unicast_link_local() || ip.is_unique_local() {
        return false;
    }

    let segments = ip.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    true
}
