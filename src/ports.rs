use crate::{
    common_ports::MOST_COMMON_PORTS_100,
    model::{Port, Subdomain},
};
use rayon::prelude::*;
use std::net::{SocketAddr, ToSocketAddrs};
use std::{net::TcpStream, time::Duration};

pub fn scan_ports(mut subdomain: Subdomain) -> Subdomain {
    // println!("->> Scanning ports for: {}", subdomain.domain);

    let socket_addresses: Vec<SocketAddr> =
        match format!("{}:1024", subdomain.domain).to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                eprintln!(
                    "port scanner: Creating socket address failed for {}: {}",
                    subdomain.domain, e
                );
                return subdomain;
            }
        };

    if socket_addresses.is_empty() {
        return subdomain;
    }

    subdomain.open_ports = MOST_COMMON_PORTS_100
        .into_par_iter()
        .map(|port| scan_port(socket_addresses[0], *port))
        .filter(|port| port.is_open) // filter closed ports
        .collect();

    subdomain.has_address = true;

    subdomain
}

fn scan_port(mut socket_address: SocketAddr, port: u16) -> Port {
    let timeout = Duration::from_secs(3);
    socket_address.set_port(port);

    let is_open = TcpStream::connect_timeout(&socket_address, timeout).is_ok();

    Port { port, is_open }
}
