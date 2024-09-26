use crate::{
    common_ports::MOST_COMMON_PORTS_100,
    model::{Port, Subdomain},
    PORT_TIMEOUT,
};
use futures::{stream, StreamExt};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Instant,
};
use tokio::net::TcpStream;

#[tracing::instrument(skip(subdomain), fields(subdomain = subdomain.domain))]
pub async fn scan_ports(concurrency: usize, mut subdomain: Subdomain) -> Subdomain {
    tracing::debug!("Scanning");
    let now = Instant::now();

    let socket_addresses: Vec<SocketAddr> = format!("{}:1024", &subdomain.domain)
        .to_socket_addrs()
        .expect("port scanner: Creating socket address")
        .collect();

    if socket_addresses.is_empty() {
        return subdomain;
    }

    let socket_address = socket_addresses[0];

    subdomain.open_ports = stream::iter(
        // we clone to avoid some borrowing issues
        MOST_COMMON_PORTS_100.to_owned(),
    )
    .map(|port| scan_port(socket_address, port))
    .buffer_unordered(concurrency)
    .filter(|p| futures::future::ready(p.is_open))
    .collect::<Vec<Port>>()
    .await;

    tracing::debug!("Scanned in {:?}", now.elapsed());

    subdomain
}

#[tracing::instrument(skip(socket_address))]
async fn scan_port(mut socket_address: SocketAddr, port: u16) -> Port {
    tracing::trace!("Scanning");
    socket_address.set_port(port);
    let start = Instant::now();

    let is_open = matches!(
        tokio::time::timeout(PORT_TIMEOUT, TcpStream::connect(&socket_address)).await,
        Ok(Ok(_)),
    );

    let time_taken = start.elapsed();
    tracing::trace!("Open {} in {:?}", port, time_taken);
    Port { port, is_open }
}
