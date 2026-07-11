use std::error::Error;

use crate::config::Config;

use super::{
    CliCommand, SnapshotCommand,
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
        CliCommand::Snapshot {
            store,
            integrity_key_file,
            message,
        } => {
            let config = Config::load(config_path)?;
            let store = snapshot_store(store, integrity_key_file.as_deref())?;
            let snapshot = store.snapshot_config(&config, message.as_deref())?;
            println!("snapshot: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!("current: {}", store.root().join("current").display());
            Ok(())
        }
        CliCommand::Rollback {
            store,
            integrity_key_file,
            to,
        } => {
            let store = snapshot_store(store, integrity_key_file.as_deref())?;
            let snapshot = store.rollback_target(to.as_deref())?;
            println!("rollback target: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!(
                "action: current pointer updated; reload classification is still required before live apply"
            );
            Ok(())
        }
        CliCommand::Snapshots {
            store,
            integrity_key_file,
            action,
        } => {
            let store = snapshot_store(store, integrity_key_file.as_deref())?;
            if let Some(action) = action {
                return run_snapshot_action(&store, action);
            }
            let current = store.current_id()?;
            for entry in store.list_entries()? {
                let marker = if current.as_deref() == Some(entry.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                let message = entry
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.metadata.message.as_deref())
                    .unwrap_or("no message");
                println!(
                    "{marker} {} {} {}",
                    entry.id,
                    entry.status.as_str(),
                    message.replace('\n', " ")
                );
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

fn snapshot_store(
    root: &std::path::Path,
    key_file: Option<&std::path::Path>,
) -> Result<fluxheim_snapshot::SnapshotStore, Box<dyn Error + Send + Sync>> {
    match key_file {
        #[cfg(feature = "proxy")]
        Some(key_file) => Ok(fluxheim_snapshot::SnapshotStore::with_integrity_key_file(
            root,
            key_file,
            std::sync::Arc::new(crate::internal_crypto::FluxheimSnapshotCryptoProvider(
                crate::internal_crypto::admin_mac_provider(),
            )),
        )?),
        #[cfg(not(feature = "proxy"))]
        Some(_) => Err("authenticated snapshots require a proxy-enabled Fluxheim build".into()),
        None => Ok(fluxheim_snapshot::SnapshotStore::new(root)),
    }
}

fn run_snapshot_action(
    store: &fluxheim_snapshot::SnapshotStore,
    action: &SnapshotCommand,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match action {
        SnapshotCommand::Show { id } => {
            let snapshot = store.snapshot(id)?;
            println!("id: {}", snapshot.id);
            println!("generation: {}", snapshot.metadata.generation);
            println!(
                "parent: {}",
                snapshot.metadata.parent_id.as_deref().unwrap_or("none")
            );
            println!("created_unix_secs: {}", snapshot.metadata.created_unix_secs);
            println!("integrity: {}", snapshot.integrity.as_str());
            println!("config: {}", snapshot.config_path.display());
            Ok(())
        }
        SnapshotCommand::Diff { old, new } => {
            let diff = store.diff(old, new)?;
            println!("old: {}", diff.old);
            println!("new: {}", diff.new);
            for field in diff.changed_top_level_fields {
                println!("changed: {field}");
            }
            Ok(())
        }
        SnapshotCommand::Verify { id } => {
            println!("integrity: {}", store.verify(id)?.as_str());
            Ok(())
        }
        SnapshotCommand::Doctor => {
            let report = store.doctor()?;
            println!("healthy: {}", report.healthy);
            println!("checked_snapshots: {}", report.checked_snapshots);
            println!(
                "authenticated_snapshots: {}",
                report.authenticated_snapshots
            );
            println!("unverified_snapshots: {}", report.unverified_snapshots);
            for issue in &report.issues {
                println!("issue: {issue}");
            }
            if report.healthy {
                Ok(())
            } else {
                Err("snapshot doctor found store integrity issues".into())
            }
        }
        SnapshotCommand::Prune {
            keep,
            older_than_days,
        } => {
            let report = store.prune(&fluxheim_snapshot::SnapshotPruneOptions {
                keep: *keep,
                older_than: older_than_days
                    .map(|days| std::time::Duration::from_secs(days.saturating_mul(86_400))),
                protected_ids: Vec::new(),
            })?;
            println!("deleted: {}", report.deleted.len());
            println!("retained: {}", report.retained);
            for id in report.deleted {
                println!("pruned: {id}");
            }
            Ok(())
        }
    }
}
