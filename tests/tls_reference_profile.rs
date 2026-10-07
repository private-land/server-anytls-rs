use std::sync::Arc;

use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ServerConfig, ServerConnection};

fn configs(client_auth: bool) -> (ServerConfig, ClientConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap();
    let server = if client_auth {
        server.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots.clone()),
                provider.clone(),
            )
            .build()
            .unwrap(),
        )
    } else {
        server.with_no_client_auth()
    };
    let server = server
        .with_single_cert(vec![cert.cert.der().clone()], key.clone_key().into())
        .unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let client = if client_auth {
        client
            .with_client_auth_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap()
    } else {
        client.with_no_client_auth()
    };
    (server, client)
}

fn feed_server(server: &mut ServerConnection, wire: &[u8]) {
    let mut wire = wire;
    while !wire.is_empty() {
        assert!(server.read_tls(&mut wire).unwrap() > 0);
        server.process_new_packets().unwrap();
    }
}

fn feed_client(client: &mut ClientConnection, wire: &[u8]) {
    let mut wire = wire;
    while !wire.is_empty() {
        assert!(client.read_tls(&mut wire).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
}

fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    first_flight_records: usize,
) -> (ServerConnection, ClientConnection) {
    let mut server = ServerConnection::new(server).unwrap();
    let mut client =
        ClientConnection::new(client, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    feed_server(&mut server, &wire);
    wire.clear();
    server.write_tls(&mut wire).unwrap();
    let mut offset = 0;
    let mut encrypted = 0;
    while offset < wire.len() {
        encrypted += usize::from(wire[offset] == 23);
        offset += 5 + u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
    }
    assert_eq!(offset, wire.len());
    assert_eq!(encrypted, first_flight_records);
    assert!(server.is_handshaking());
    feed_client(&mut client, &wire);
    for _ in 0..10 {
        wire.clear();
        client.write_tls(&mut wire).unwrap();
        feed_server(&mut server, &wire);
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        feed_client(&mut client, &wire);
        if !server.is_handshaking() && !client.is_handshaking() {
            return (server, client);
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn reference_without_tickets_completes_handshake() {
    let (mut server, client) = configs(false);
    server.reference_server_profile = true;
    server.send_tls13_tickets = 0;
    let (_, client) = handshake(Arc::new(server), Arc::new(client), 4);
    assert_eq!(client.tls13_tickets_received(), 0);
}

#[test]
fn reference_client_auth_defers_ticket_until_verified_finished() {
    let (mut server, client) = configs(true);
    server.reference_server_profile = true;
    server.send_tls13_tickets = 1;
    let (server, client) = handshake(Arc::new(server), Arc::new(client), 5);
    assert_eq!(server.peer_certificates().unwrap().len(), 1);
    assert_eq!(client.tls13_tickets_received(), 1);
}

#[test]
fn reference_early_data_configuration_keeps_normal_ticket_path() {
    let (mut server, client) = configs(false);
    server.reference_server_profile = true;
    server.max_early_data_size = 128;
    server.send_tls13_tickets = 1;
    let (_, client) = handshake(Arc::new(server), Arc::new(client), 4);
    assert_eq!(client.tls13_tickets_received(), 1);
}

#[test]
fn reference_and_legacy_tickets_resume_verified_sessions() {
    for reference in [false, true] {
        let (mut server, client) = configs(false);
        server.reference_server_profile = reference;
        server.send_tls13_tickets = 1;
        server.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
        let server = Arc::new(server);
        let client = Arc::new(client);
        let (_, first) = handshake(
            server.clone(),
            client.clone(),
            if reference { 5 } else { 1 },
        );
        assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(first.tls13_tickets_received(), 1);
        let (_, second) = handshake(server, client, if reference { 3 } else { 1 });
        assert_eq!(second.handshake_kind(), Some(HandshakeKind::Resumed));
    }
}

#[test]
fn reference_profile_does_not_change_quic_server_hello() {
    for reference in [false, true] {
        let (mut server, mut client) = configs(false);
        server.reference_server_profile = reference;
        server.alpn_protocols = vec![b"h3".to_vec()];
        client.alpn_protocols = server.alpn_protocols.clone();
        let mut server = rustls::quic::ServerConnection::new(
            Arc::new(server),
            rustls::quic::Version::V1,
            Vec::new(),
        )
        .unwrap();
        let mut client = rustls::quic::ClientConnection::new(
            Arc::new(client),
            rustls::quic::Version::V1,
            ServerName::try_from("localhost").unwrap(),
            Vec::new(),
        )
        .unwrap();
        let mut wire = Vec::new();
        client.write_hs(&mut wire);
        server.read_hs(&wire).unwrap();
        wire.clear();
        server.write_hs(&mut wire);
        assert_eq!(wire[0], 2); // ServerHello
        let mut offset = 44 + wire[38] as usize;
        let mut extensions = Vec::new();
        while offset < wire.len() {
            extensions.push(u16::from_be_bytes([wire[offset], wire[offset + 1]]));
            offset += 4 + u16::from_be_bytes([wire[offset + 2], wire[offset + 3]]) as usize;
        }
        assert_eq!(offset, wire.len());
        assert_eq!(extensions, [51, 43]);
        client.read_hs(&wire).unwrap();
        for _ in 0..10 {
            wire.clear();
            server.write_hs(&mut wire);
            client.read_hs(&wire).unwrap();
            wire.clear();
            client.write_hs(&mut wire);
            server.read_hs(&wire).unwrap();
            if !server.is_handshaking() && !client.is_handshaking() {
                break;
            }
        }
        assert!(!server.is_handshaking() && !client.is_handshaking());
        assert_eq!(server.alpn_protocol(), Some(&b"h3"[..]));
    }
}
