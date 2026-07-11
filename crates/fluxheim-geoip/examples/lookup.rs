use std::net::IpAddr;
use std::path::PathBuf;

use fluxheim_config::{GeoIpConfig, GeoIpDatabaseConfig, GeoIpProvider};
use fluxheim_geoip::{GeoIpPolicyUsage, GeoIpRuntime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let provider = match arguments.next().as_deref() {
        Some("circl-geo-open") => GeoIpProvider::CirclGeoOpen,
        Some("maxmind") => GeoIpProvider::Maxmind,
        _ => return Err("usage: lookup <circl-geo-open|maxmind> <database.mmdb> <ip>...".into()),
    };
    let path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing MMDB path")?;
    let addresses = arguments
        .map(|value| value.parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()?;
    if addresses.is_empty() {
        return Err("at least one IP address is required".into());
    }

    let config = GeoIpConfig {
        enabled: true,
        fallback_enabled: true,
        databases: vec![GeoIpDatabaseConfig { provider, path }],
    };
    let runtime = GeoIpRuntime::from_config(
        &config,
        GeoIpPolicyUsage {
            country: true,
            asn: true,
        },
    )?
    .ok_or("GeoIP runtime was not enabled")?;

    for address in addresses {
        match runtime.lookup(address) {
            Some(context) => println!(
                "{address}\tcountry={}\tasn={}",
                context.country_iso().unwrap_or("-"),
                context
                    .asn()
                    .map(|asn| asn.to_string())
                    .as_deref()
                    .unwrap_or("-")
            ),
            None => println!("{address}\tcountry=-\tasn=-"),
        }
    }
    Ok(())
}
