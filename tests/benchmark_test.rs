//! Optional throughput measurement; correctness is covered by security_and_flow_tests.
use otium_flow::protocol::{TransferManager, TrustManager};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[tokio::test]
#[ignore = "explicit local throughput measurement, not a portable performance guarantee"]
async fn encrypted_10mb_loopback_measurement() {
    let base = std::env::temp_dir().join(format!("flow-benchmark-{}", uuid::Uuid::new_v4()));
    let a = Arc::new(
        TrustManager::try_with_self_id(base.join("a"), uuid::Uuid::new_v4().to_string()).unwrap(),
    );
    let b = Arc::new(
        TrustManager::try_with_self_id(base.join("b"), uuid::Uuid::new_v4().to_string()).unwrap(),
    );
    a.trust_peer_with_secret(b.self_id().into(), "B".into(), &b.pairing_code().await)
        .await
        .unwrap();
    b.trust_peer_with_secret(a.self_id().into(), "A".into(), &a.pairing_code().await)
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver = Arc::new(TransferManager::with_trust(
        address.port(),
        base.join("received"),
        b.clone(),
    ));
    let (tx, _rx) = mpsc::unbounded_channel();
    receiver.start_with_listener(listener, tx).await;
    let sender = TransferManager::with_trust(0, base.join("source"), a);
    let source = base.join("payload.bin");
    let data: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &data).unwrap();
    let started = Instant::now();
    sender
        .send_secure_file(
            address,
            b.self_id(),
            &source,
            &uuid::Uuid::new_v4().to_string(),
            Arc::new(AtomicBool::new(false)),
            |_, _, _, _| {},
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(base.join("received/payload.bin")).unwrap(),
        data
    );
    eprintln!(
        "Encrypted 10 MB loopback: {:.2} MB/s",
        10.0 / started.elapsed().as_secs_f64()
    );
    if base.parent() == Some(std::env::temp_dir().as_path())
        && base
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("flow-benchmark-")
    {
        let _ = std::fs::remove_dir_all(base);
    }
}
