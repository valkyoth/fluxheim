use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SerialNumber, date_time_ymd,
};

pub(crate) struct RevokedClientCertificateFixture {
    pub ca_pem: String,
    #[cfg(feature = "tls-rustls-backend")]
    pub client_der: Vec<u8>,
    #[cfg(feature = "tls-openssl")]
    pub client_pem: String,
    #[cfg(feature = "tls-openssl")]
    pub client_key_pem: String,
    pub crl_pem: String,
    pub expired_crl_pem: String,
}

pub(crate) struct HierarchicalClientCertificateFixture {
    pub root_ca_pem: String,
    #[cfg(feature = "tls-rustls-backend")]
    pub intermediate_der: Vec<u8>,
    #[cfg(feature = "tls-openssl")]
    pub intermediate_pem: String,
    #[cfg(feature = "tls-rustls-backend")]
    pub client_der: Vec<u8>,
    #[cfg(feature = "tls-openssl")]
    pub client_pem: String,
    #[cfg(feature = "tls-openssl")]
    pub client_key_pem: String,
    pub crl_bundle_pem: String,
    pub intermediate_crl_pem: String,
}

pub(crate) fn revoked_client_certificate_fixture() -> RevokedClientCertificateFixture {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Fluxheim test client CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

    let serial_number = SerialNumber::from(42_u64);
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "revoked Fluxheim test client");
    client_params.serial_number = Some(serial_number.clone());
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client = client_params.signed_by(&client_key, &ca).unwrap();

    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2025, 1, 1),
        next_update: date_time_ymd(2035, 1, 1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number,
            revocation_time: date_time_ymd(2025, 1, 2),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca)
    .unwrap();
    let expired_crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2020, 1, 1),
        next_update: date_time_ymd(2021, 1, 1),
        crl_number: SerialNumber::from(2_u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca)
    .unwrap();

    RevokedClientCertificateFixture {
        ca_pem: ca.pem(),
        #[cfg(feature = "tls-rustls-backend")]
        client_der: client.der().to_vec(),
        #[cfg(feature = "tls-openssl")]
        client_pem: client.pem(),
        #[cfg(feature = "tls-openssl")]
        client_key_pem: client_key.serialize_pem(),
        crl_pem: crl.pem().unwrap(),
        expired_crl_pem: expired_crl.pem().unwrap(),
    }
}

pub(crate) fn hierarchical_client_certificate_fixture() -> HierarchicalClientCertificateFixture {
    let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Fluxheim test root CA");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

    let intermediate_serial = SerialNumber::from(100_u64);
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Fluxheim test intermediate client CA");
    intermediate_params.serial_number = Some(intermediate_serial);
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let intermediate =
        CertifiedIssuer::signed_by(intermediate_params, KeyPair::generate().unwrap(), &root)
            .unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "hierarchical Fluxheim test client");
    client_params.serial_number = Some(SerialNumber::from(101_u64));
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client = client_params.signed_by(&client_key, &intermediate).unwrap();

    let root_crl = empty_crl(&root, 10);
    let intermediate_crl = empty_crl(&intermediate, 11);
    let intermediate_crl_pem = intermediate_crl.pem().unwrap();
    let crl_bundle_pem = format!("{}{}", root_crl.pem().unwrap(), intermediate_crl_pem);

    HierarchicalClientCertificateFixture {
        root_ca_pem: root.pem(),
        #[cfg(feature = "tls-rustls-backend")]
        intermediate_der: intermediate.der().to_vec(),
        #[cfg(feature = "tls-openssl")]
        intermediate_pem: intermediate.pem(),
        #[cfg(feature = "tls-rustls-backend")]
        client_der: client.der().to_vec(),
        #[cfg(feature = "tls-openssl")]
        client_pem: client.pem(),
        #[cfg(feature = "tls-openssl")]
        client_key_pem: client_key.serialize_pem(),
        crl_bundle_pem,
        intermediate_crl_pem,
    }
}

fn empty_crl(
    issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
    number: u64,
) -> rcgen::CertificateRevocationList {
    CertificateRevocationListParams {
        this_update: date_time_ymd(2025, 1, 1),
        next_update: date_time_ymd(2035, 1, 1),
        crl_number: SerialNumber::from(number),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
}
