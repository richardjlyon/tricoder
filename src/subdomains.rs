use crate::{
    model::{CrtShEntry, Subdomain},
    Error,
};
use futures::stream;
use futures::StreamExt;
use itertools::Itertools;
use reqwest::Client;
use std::{
    iter,
    time::{Duration, Instant},
};
use tracing::info;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    AsyncResolver, TokioAsyncResolver,
};

type DnsResolver = AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub async fn enumerate(http_client: &Client, target: &str) -> Result<Vec<Subdomain>, Error> {
    let start = Instant::now();
    let body = http_client
        .get(format!("https://crt.sh/?q=%25.{}&output=json", target))
        .send()
        .await?
        .text()
        .await?;

    let entries =
        serde_json::from_str::<Vec<CrtShEntry>>(&body).map_err(|_| Error::Decoding(body))?;

    let crt_sh_elapsed = start.elapsed();

    info!("Found {} entries in {:?}", entries.len(), crt_sh_elapsed);

    // clean and dedup results
    let subdomains = entries
        .iter()
        .flat_map(|entry| {
            entry
                .name_value
                .split("\n")
                .map(|subdomain| subdomain.trim())
        })
        .filter(|subdomain| *subdomain != target)
        .filter(|subdomain| !subdomain.contains("*"))
        .chain(iter::once(target))
        .unique();

    let dns_resolver = build_resolver(200);

    let subdomains: Vec<_> = stream::iter(subdomains)
        .map(|subdomain| {
            let dns_resolver = dns_resolver.clone();
            async move { (resolves(&dns_resolver, &subdomain).await, subdomain) }
        })
        // this needs a future, so we map into a future and filter _after_
        // | _ | _ | _ | <- `n` 'work buckets' to query at once
        .buffer_unordered(10)
        .filter_map(|(dns_resolves, subdomain)| async move {
            dns_resolves.then(|| Subdomain {
                domain: subdomain.to_owned(),
                has_address: false,
                open_ports: Vec::new(),
            })
        })
        .collect()
        .await;

    let subdomains_elapsed = start.elapsed();

    info!(
        "Found {} subdomains in {:?}",
        subdomains.len(),
        subdomains_elapsed - crt_sh_elapsed
    );

    Ok(subdomains)
}

fn build_resolver(millis: u64) -> TokioAsyncResolver {
    let mut dns_resolver_opts = ResolverOpts::default();
    dns_resolver_opts.timeout = Duration::from_millis(millis);

    let dns_resolver = AsyncResolver::tokio(ResolverConfig::default(), dns_resolver_opts)
        .expect("subdomain resolver: building DNS client");
    dns_resolver
}

#[tracing::instrument(skip(dns_resolver))]
pub async fn resolves(dns_resolver: &DnsResolver, domain: &str) -> bool {
    tracing::trace!("Resolving");
    let value = dns_resolver.lookup_ip(domain).await.is_ok();
    tracing::trace!("Resolved");
    value
}
