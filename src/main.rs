use futures::{stream, StreamExt};
use reqwest::Client;
use std::{
    env,
    time::{Duration, Instant},
};
use tracing::info;

mod error;
pub use error::Error;
mod model;
mod ports;
mod subdomains;
use model::Subdomain;
mod common_ports;

const PORTS_CONCURRENCY: usize = 200;
const SUBDOMAINS_CONCURRENCY: usize = 100;
const CRT_SH_TIMEOUT: Duration = Duration::from_secs(10);
const PORT_TIMEOUT: Duration = Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err(Error::CliUsage.into());
    }

    let target = args[1].as_str();

    let http_client = Client::builder().timeout(CRT_SH_TIMEOUT).build()?;

    let scan_start = Instant::now();

    let subdomains = subdomains::enumerate(&http_client, target).await?;

    let domain_search = scan_start.elapsed();
    info!(
        "Found {} subdomains in {:?}",
        subdomains.len(),
        domain_search
    );

    // Concurrent stream method 1: Using buffer_unordered + collect
    let scan_result: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|subdomain: Subdomain| tokio::spawn(ports::scan_ports(PORTS_CONCURRENCY, subdomain)))
        .buffer_unordered(SUBDOMAINS_CONCURRENCY)
        .map(|result| result.unwrap())
        .collect()
        .await;

    let complete_scan = scan_start.elapsed();
    info!("Scan completed in {:?}", complete_scan);
    info!(
        "Excess time: {:?}",
        complete_scan - domain_search - PORT_TIMEOUT
    );

    for subdomain in scan_result {
        println!("{}:", &subdomain.domain);
        for port in &subdomain.open_ports {
            println!("    {}: open", port.port);
        }

        println!("");
    }

    Ok(())
}
