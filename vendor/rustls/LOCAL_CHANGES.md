# Local changes to rustls 0.23.43

This directory vendors the crates.io rustls 0.23.43 source and its original
Apache-2.0, ISC and MIT licenses. The root Cargo patch unifies the version used
by tokio-rustls and the panel dependencies.

The added `ServerConfig::reference_server_profile` defaults to false. When
enabled for an AnyTLS server it changes only TLS 1.3 TCP record organization
and ServerHello extension serialization:

- `common_state.rs`: track encoded handshake-message boundaries only for the
  opted-in TCP server flight and emit each message in a separate record.
  Other flights do not allocate a boundary array. Transcript bytes and hashes
  are unchanged.
- `server/server_conn.rs`, `server/builder.rs`: expose the opt-in field.
- `server/tls13.rs`: select the record and extension mode for that server.
- `tls13/key_schedule.rs`, `server/tls13.rs`: in the profile's TCP/no-client-auth/
  no-0-RTT path with tickets enabled, predict the client Finished solely to derive a resumption PSK
  and issue tickets alongside the server Finished (RFC 8446 section 4.6.1).
  Do not add the ticket to the handshake transcript or admit traffic early.
- `msgs/handshake.rs`: optionally encode supported_versions before key_share.

Client configurations, QUIC, TLS 1.2, cryptographic primitives, Finished
verification and ticket encryption retain upstream behavior. Actual client
Finished verification remains mandatory before traffic admission. Other paths
issue tickets after the client's Finished is verified.

When upgrading rustls, refresh the vendor source, reapply these changes and
run the root TLS alert, first-flight, resumption, lifecycle and nested HTTPS
tests in both profile modes. Do not defer upstream security updates because
of this patch.
