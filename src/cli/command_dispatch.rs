use std::error::Error;

use crate::config::Config;

use super::{
    CliCommand,
    acme_init_commands::run_acme_init_command,
    acme_renew_commands::run_acme_renew_command,
    cache_key_command::run_cache_key_command,
    cache_lookup_command::run_cache_lookup_command,
    cache_warm_command::run_cache_warm_command,
    command_options::{AcmeInitOptions, CacheKeyOptions, CacheLookupOptions, CacheWarmOptions},
    crypto_commands::{run_cache_keygen_command, run_crypto_diagnostics_command},
};

pub(super) fn run_command(
    command: &CliCommand,
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command {
        CliCommand::Snapshot { store, message } => {
            let config = Config::load(config_path)?;
            let store = fluxheim_snapshot::SnapshotStore::new(store);
            let snapshot = store.snapshot_config(&config, message.as_deref())?;
            println!("snapshot: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!("current: {}", store.root().join("current").display());
            Ok(())
        }
        CliCommand::Rollback { store, to } => {
            let store = fluxheim_snapshot::SnapshotStore::new(store);
            let snapshot = store.rollback_target(to.as_deref())?;
            println!("rollback target: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!(
                "action: current pointer updated; reload classification is still required before live apply"
            );
            Ok(())
        }
        CliCommand::Snapshots { store } => {
            let store = fluxheim_snapshot::SnapshotStore::new(store);
            let current = store.current_id()?;
            for snapshot in store.list()? {
                let marker = if current.as_deref() == Some(snapshot.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                let message = snapshot.metadata.message.as_deref().unwrap_or("no message");
                println!("{marker} {} {}", snapshot.id, message.replace('\n', " "));
            }
            Ok(())
        }
        CliCommand::Crypto => run_crypto_diagnostics_command(config_path),
        CliCommand::AcmeRenew { force_renew, all } => {
            if *all {
                eprintln!("warning: --all is deprecated; use --force-renew");
            }
            run_acme_renew_command(config_path, *force_renew || *all)
        }
        CliCommand::AcmeInit {
            issuer,
            email,
            kid_file,
            hmac_key_file,
            non_interactive,
            force,
            no_systemd,
            output,
            storage,
            secrets_dir,
            systemd_dropin_dir,
        } => run_acme_init_command(AcmeInitOptions {
            issuer: *issuer,
            email: email.clone(),
            kid_file: kid_file.clone(),
            hmac_key_file: hmac_key_file.clone(),
            non_interactive: *non_interactive,
            force: *force,
            no_systemd: *no_systemd,
            output: output.clone(),
            storage: storage.clone(),
            secrets_dir: secrets_dir.clone(),
            systemd_dropin_dir: systemd_dropin_dir.clone(),
        }),
        CliCommand::CacheKeygen => run_cache_keygen_command(),
        CliCommand::CacheWarm {
            listen,
            host,
            headers,
            paths,
            input,
            timeout_secs,
            max_targets,
            fail_fast,
            dry_run,
            repeat,
            allow_statuses,
            cache_status_header,
            expect_cache_statuses,
            expect_cache_status_sequence,
        } => run_cache_warm_command(CacheWarmOptions {
            config_path,
            listen: listen.clone(),
            host: host.clone(),
            headers: headers.clone(),
            paths: paths.clone(),
            input: input.clone(),
            timeout_secs: *timeout_secs,
            max_targets: *max_targets,
            fail_fast: *fail_fast,
            dry_run: *dry_run,
            repeat: *repeat,
            allow_statuses: allow_statuses.clone(),
            cache_status_header: cache_status_header.clone(),
            expect_cache_statuses: expect_cache_statuses.clone(),
            expect_cache_status_sequence: expect_cache_status_sequence.clone(),
        }),
        CliCommand::CacheKey {
            host,
            headers,
            method,
            path,
            query,
            expect_eligible,
            expect_ineligible,
            expect_reason,
            expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled,
            expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled,
            expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled,
            expect_disk_tier_enabled,
            expect_storage_tiers,
            expect_scope,
            expect_vhost,
            expect_route,
            expect_namespace,
            expect_key_namespace,
            expect_user_tag,
        } => run_cache_key_command(CacheKeyOptions {
            config_path,
            host: host.clone(),
            headers: headers.clone(),
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            expect_eligible: *expect_eligible,
            expect_ineligible: *expect_ineligible,
            expect_reason: expect_reason.clone(),
            expect_cache_lock_enabled: *expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs: *expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: *expect_cache_predictor_enabled,
            expect_origin_protection_enabled: *expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills:
                *expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: *expect_peer_fill_enabled,
            expect_peer_fill_peers: *expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests: *expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: *expect_memory_tier_enabled,
            expect_disk_tier_enabled: *expect_disk_tier_enabled,
            expect_storage_tiers: *expect_storage_tiers,
            expect_scope: expect_scope.clone(),
            expect_vhost: expect_vhost.clone(),
            expect_route: expect_route.clone(),
            expect_namespace: expect_namespace.clone(),
            expect_key_namespace: expect_key_namespace.clone(),
            expect_user_tag: expect_user_tag.clone(),
        }),
        CliCommand::CacheLookup {
            host,
            headers,
            method,
            path,
            query,
            require_object,
            expect_objects,
            expect_ineligible,
            expect_reason,
            expect_freshness_states,
            expect_statuses,
            expect_tiers,
            expect_fresh_ttl_secs,
            expect_body_bytes,
            expect_header_names,
            expect_headers,
            expect_cache_tags,
            expect_purge_indexed,
            expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled,
            expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled,
            expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled,
            expect_disk_tier_enabled,
            expect_storage_tiers,
            expect_scope,
            expect_vhost,
            expect_route,
            expect_namespace,
            expect_key_namespace,
            expect_user_tag,
            expect_serve_stale_if_error,
            expect_serve_stale_while_revalidate,
        } => run_cache_lookup_command(CacheLookupOptions {
            config_path,
            host: host.clone(),
            headers: headers.clone(),
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            require_object: *require_object,
            expect_objects: *expect_objects,
            expect_ineligible: *expect_ineligible,
            expect_reason: expect_reason.clone(),
            expect_freshness_states: expect_freshness_states.clone(),
            expect_statuses: expect_statuses.clone(),
            expect_tiers: expect_tiers.clone(),
            expect_fresh_ttl_secs: expect_fresh_ttl_secs.clone(),
            expect_body_bytes: expect_body_bytes.clone(),
            expect_header_names: expect_header_names.clone(),
            expect_headers: expect_headers.clone(),
            expect_cache_tags: expect_cache_tags.clone(),
            expect_purge_indexed: *expect_purge_indexed,
            expect_cache_lock_enabled: *expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs: *expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: *expect_cache_predictor_enabled,
            expect_origin_protection_enabled: *expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills:
                *expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: *expect_peer_fill_enabled,
            expect_peer_fill_peers: *expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests: *expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: *expect_memory_tier_enabled,
            expect_disk_tier_enabled: *expect_disk_tier_enabled,
            expect_storage_tiers: *expect_storage_tiers,
            expect_scope: expect_scope.clone(),
            expect_vhost: expect_vhost.clone(),
            expect_route: expect_route.clone(),
            expect_namespace: expect_namespace.clone(),
            expect_key_namespace: expect_key_namespace.clone(),
            expect_user_tag: expect_user_tag.clone(),
            expect_serve_stale_if_error: *expect_serve_stale_if_error,
            expect_serve_stale_while_revalidate: *expect_serve_stale_while_revalidate,
        }),
    }
}
