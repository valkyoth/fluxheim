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
