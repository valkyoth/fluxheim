#!/usr/bin/env sh
set -eu

tls_root="/opt/fluxheim-evidence/tls"
ca_key="$tls_root/ca-key.pem"
ca_certificate="$tls_root/ca.pem"
server_request="$tls_root/server.csr"
server_certificate="$tls_root/server-cert.pem"
server_key="$tls_root/server-key.pem"

umask 077

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -days 30 \
    -subj '/CN=Fluxheim FIPS Evidence Test CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$ca_key" \
    -out "$ca_certificate" >/dev/null 2>&1

openssl req \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -subj '/CN=fips.test' \
    -addext 'subjectAltName=DNS:fips.test,DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$server_key" \
    -out "$server_request" >/dev/null 2>&1

openssl x509 \
    -req \
    -in "$server_request" \
    -CA "$ca_certificate" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -days 30 \
    -sha256 \
    -copy_extensions copy \
    -out "$server_certificate" >/dev/null 2>&1

openssl verify -CAfile "$ca_certificate" -verify_hostname localhost "$server_certificate"
openssl verify -CAfile "$ca_certificate" -verify_hostname fips.test "$server_certificate"

rm -f "$ca_key" "$server_request" "$tls_root/ca.srl"
chmod 0644 "$ca_certificate" "$server_certificate"
chmod 0600 "$server_key"
