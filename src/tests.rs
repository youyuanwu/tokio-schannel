use std::time::Duration;

use schannel::{
    cert_context::CertContext,
    cert_store::CertStore,
    schannel_cred::{Direction, SchannelCred},
    tls_stream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{TlsAcceptor, TlsConnector};

const FRIENDLY_NAME: &str = "YARRP-Test";

#[tokio::test]
async fn test_schannel() {
    let cert = find_test_cert().unwrap();
    // open listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // run server
    let server_h = tokio::spawn(async move {
        let creds = SchannelCred::builder()
            .cert(cert)
            .acquire(Direction::Inbound)
            .unwrap();
        let builder = tls_stream::Builder::new();
        let mut acceptor = TlsAcceptor::new(builder);
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(creds, tcp_stream).await.unwrap();
        let mut buf = [0_u8; 1024];
        let len = tls_stream.read(&mut buf).await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(buf[..3], [1, 2, 3]);
    });

    // sleep wait for server
    tokio::time::sleep(Duration::from_secs(1)).await;

    // run client
    let client_h = tokio::spawn(async move {
        let stream = TcpStream::connect(&addr).await.unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut builder = tls_stream::Builder::new();
        builder.verify_callback(|_| {
            // ignore errors
            Ok(())
        });
        builder.domain("localhost");
        let mut tls_connector = TlsConnector::new(builder);

        let mut tls_stream = tls_connector.connect(creds, stream).await.unwrap();
        let len = tls_stream.write(&[1, 2, 3]).await.unwrap();
        assert_eq!(len, 3);
    });

    client_h.await.unwrap();
    server_h.await.unwrap();
}

fn find_test_cert() -> Option<CertContext> {
    let store = CertStore::open_current_user("My").unwrap();
    for cert in store.certs() {
        let name = match cert.friendly_name() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if name != FRIENDLY_NAME {
            continue;
        }
        return Some(cert);
    }
    None
}
