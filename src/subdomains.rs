use crate::{
    model::{CrtShEntry, Subdomain},
    Error,
};
use futures::stream;
use futures::StreamExt;
use reqwest::Client;
use std::{collections::HashSet, time::Duration};
use tracing::info;
use trust_dns_resolver::{config::{ResolverConfig, ResolverOpts}, name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime}, AsyncResolver, TokioAsyncResolver};

type DnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub async fn enumerate(http_client: &Client, target: &str) -> Result<Vec<Subdomain>, Error> {
    let entries: Vec<CrtShEntry> = http_client
        .get(format!("https://crt.sh/?q=%25.{}&output=json", target))
        .send()
        .await?
        .json()
        .await?;

    info!("Found {} entries", entries.len());

    // clean and dedup results
    let mut subdomains: HashSet<String> = entries
        .into_iter()
        .flat_map(|entry| {
            entry
                .name_value
                .split("\n")
                .map(|subdomain| subdomain.trim().to_string())
                .collect::<Vec<String>>()
        })
        .filter(|subdomain: &String| subdomain != target)
        .filter(|subdomain: &String| !subdomain.contains("*"))
        .collect();

    subdomains.insert(target.to_string());

    let dns_resolver = build_resolver(500);

    info!("Resolving {} subdomains", subdomains.len());

    let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
        .map(|domain| Subdomain {
            domain,
            has_address: false,
            open_ports: Vec::new(),
        })
        .filter_map(|subdomain| {
            let dns_resolver = dns_resolver.clone();
            async move {
                if resolves(&dns_resolver, &subdomain).await {
                    Some(subdomain)
                } else {
                    None
                }
            }
        })
        .collect()
        .await;

    Ok(subdomains)
}

fn build_resolver(millis: u64) -> TokioAsyncResolver {
    let mut dns_resolver_opts = ResolverOpts::default();
    dns_resolver_opts.timeout = Duration::from_millis(millis);

    let dns_resolver = AsyncResolver::tokio(ResolverConfig::default(), dns_resolver_opts)
        .expect("subdomain resolver: building DNS client");
    dns_resolver
}

pub async fn resolves(dns_resolver: &DnsResolver, domain: &Subdomain) -> bool {
    dns_resolver.lookup_ip(domain.domain.as_str()).await.is_ok()
}
