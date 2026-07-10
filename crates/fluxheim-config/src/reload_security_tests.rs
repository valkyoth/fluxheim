use crate::config::{Config, DownstreamProxyProtocol, TlsClientAuthConfig, TlsClientAuthMode};
use crate::reload::{ReloadImpact, ReloadReason, classify_reload};

fn assert_process_upgrade(new: Config, expected: ReloadReason) {
    assert_transition_requires_process_upgrade(&Config::default(), &new, expected);
}

fn assert_transition_requires_process_upgrade(old: &Config, new: &Config, expected: ReloadReason) {
    assert_eq!(
        classify_reload(old, new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![expected],
        }
    );
}

#[test]
fn client_auth_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tls.client_auth = TlsClientAuthConfig {
        mode: TlsClientAuthMode::Required,
        ca_path: Some("client-ca.pem".into()),
    };
    assert_process_upgrade(new, ReloadReason::TlsClientAuthChanged);
}

#[test]
fn compliance_mode_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tls.iso19790.required = true;
    assert_process_upgrade(new, ReloadReason::ComplianceModeChanged);
}

#[test]
fn proxy_protocol_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.server.proxy_protocol = DownstreamProxyProtocol::V1;
    assert_process_upgrade(new, ReloadReason::ListenerSecurityChanged);
}

#[test]
fn server_limit_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.server.limits.max_request_headers += 1;
    assert_process_upgrade(new, ReloadReason::ListenerSecurityChanged);
}

#[test]
fn stream_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.stream.enabled = true;
    assert_process_upgrade(new, ReloadReason::StreamServiceChanged);
}

#[test]
fn udp_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.udp.enabled = true;
    assert_process_upgrade(new, ReloadReason::UdpServiceChanged);
}

#[test]
fn acme_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tls.acme.enabled = true;
    assert_process_upgrade(new, ReloadReason::AcmeServiceChanged);
}

#[test]
fn cache_purger_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.cache_purger.enabled = true;
    assert_process_upgrade(new, ReloadReason::CachePurgerServiceChanged);
}

#[test]
fn tracing_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tracing.enabled = true;
    assert_process_upgrade(new, ReloadReason::TracingServiceChanged);
}

#[test]
fn certificate_lookup_change_remains_snapshot_safe() {
    let mut new = Config::default();
    new.tls
        .certificates
        .push(crate::config::StaticCertificateConfig {
            cert_path: "certificate.pem".into(),
            key_path: "key.pem".into(),
        });
    assert_eq!(
        classify_reload(&Config::default(), &new),
        ReloadImpact::Snapshot
    );
}

fn managed_acme_config() -> Config {
    toml::from_str(
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            issuer = "primary"
        "#,
    )
    .unwrap()
}

#[test]
fn nested_acme_enablement_requires_process_upgrade() {
    let new = managed_acme_config();
    let mut old = new.clone();
    old.vhosts[0].tls.acme.enabled = false;

    assert_transition_requires_process_upgrade(&old, &new, ReloadReason::AcmeServiceChanged);
    assert_transition_requires_process_upgrade(&new, &old, ReloadReason::AcmeServiceChanged);
}

#[test]
fn nested_acme_identity_and_targets_require_process_upgrade() {
    let old = managed_acme_config();
    let mut changes = Vec::new();

    let mut issuer = old.clone();
    issuer.vhosts[0].tls.acme.issuer = Some("secondary".to_owned());
    changes.push(issuer);

    let mut domains = old.clone();
    domains.vhosts[0].tls.acme.domains = vec!["certificate.example.test".to_owned()];
    changes.push(domains);

    let mut inherited_hosts = old.clone();
    inherited_hosts.vhosts[0].hosts = vec!["renamed.example.test".to_owned()];
    changes.push(inherited_hosts);

    let mut vhost_name = old.clone();
    vhost_name.vhosts[0].name = "renamed".to_owned();
    changes.push(vhost_name);

    for new in changes {
        assert_transition_requires_process_upgrade(&old, &new, ReloadReason::AcmeServiceChanged);
    }
}

fn managed_php_config() -> Config {
    toml::from_str(
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/usr/sbin/php-fpm"
            socket_dir = "/run/fluxheim/php"
        "#,
    )
    .unwrap()
}

#[test]
fn managed_php_add_remove_requires_process_upgrade() {
    let new = managed_php_config();
    let old = Config::default();

    assert_transition_requires_process_upgrade(&old, &new, ReloadReason::ManagedPhpServiceChanged);
    assert_transition_requires_process_upgrade(&new, &old, ReloadReason::ManagedPhpServiceChanged);
}

#[test]
fn managed_php_process_policy_changes_require_process_upgrade() {
    let old = managed_php_config();
    let mut changes = Vec::new();

    let mut binary = old.clone();
    binary.vhosts[0].php.fpm.php_fpm_binary = Some("/opt/php/sbin/php-fpm".into());
    changes.push(binary);

    let mut identity = old.clone();
    identity.vhosts[0].php.fpm.user = Some("www-data".to_owned());
    identity.vhosts[0].php.fpm.group = Some("www-data".to_owned());
    changes.push(identity);

    let mut environment = old.clone();
    environment.vhosts[0].php.fpm.clear_env = false;
    changes.push(environment);

    let mut socket_dir = old.clone();
    socket_dir.vhosts[0].php.fpm.socket_dir = Some("/run/fluxheim/php-next".into());
    changes.push(socket_dir);

    let mut workers = old.clone();
    workers.vhosts[0].php.fpm.process_manager = crate::config::PhpFpmProcessManager::Dynamic;
    workers.vhosts[0].php.fpm.workers = 8;
    workers.vhosts[0].php.fpm.min_spare_servers = Some(2);
    workers.vhosts[0].php.fpm.max_spare_servers = Some(4);
    changes.push(workers);

    for new in changes {
        assert_transition_requires_process_upgrade(
            &old,
            &new,
            ReloadReason::ManagedPhpServiceChanged,
        );
    }
}

#[test]
fn route_managed_php_addition_requires_process_upgrade() {
    let old = Config::default();
    let new: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [[vhosts.routes]]
            name = "application"
            path_prefix = "/app"

            [vhosts.routes.php]
            enabled = true

            [vhosts.routes.php.fpm]
            mode = "managed"
            php_fpm_binary = "/usr/sbin/php-fpm"
            socket_dir = "/run/fluxheim/php-route"
        "#,
    )
    .unwrap();

    assert_transition_requires_process_upgrade(&old, &new, ReloadReason::ManagedPhpServiceChanged);
}

#[test]
fn managed_php_request_policy_change_remains_snapshot_safe() {
    let old = managed_php_config();
    let mut new = old.clone();
    new.vhosts[0].php.request_timeout_secs += 1;
    new.vhosts[0].php.fpm.read_timeout_secs = Some(15);

    assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
}
