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

const FRIENDLY_NAME: &str = "YY-Test";

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
    get_test_cert_hash();
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

/// Use pwsh to get the test cert hash, or generate the cert.
pub fn get_test_cert_hash() -> String {
    fn get_hash() -> Option<String> {
        let output = std::process::Command::new("pwsh.exe")
                .args(["-Command", "Get-ChildItem Cert:\\CurrentUser\\My | Where-Object -Property FriendlyName -EQ -Value YY-Test | Select-Object -ExpandProperty Thumbprint -First 1"]).
                output().expect("Failed to execute command");
        assert!(output.status.success());
        let mut s = String::from_utf8(output.stdout).unwrap();
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        };
        if s.is_empty() { None } else { Some(s) }
    }
    fn gen_cert() {
        let gen_cert_cmd = "New-SelfSignedCertificate -DnsName $env:computername,localhost -FriendlyName YY-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\\CurrentUser\\My -HashAlgorithm SHA256 -Provider \"Microsoft Software Key Storage Provider\" -KeyExportPolicy Exportable";
        let output = std::process::Command::new("pwsh.exe")
            .args(["-Command", gen_cert_cmd])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .output()
            .expect("Failed to execute command");
        assert!(output.status.success());
    }
    // generate the cert if not exist
    match get_hash() {
        Some(s) => s,
        None => {
            gen_cert();
            get_hash().unwrap()
        }
    }
}
